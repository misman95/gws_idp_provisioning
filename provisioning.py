"""
Google Admin SDK Directory API -> Netskope SCIM v2
Workspace/Cloud Identity 사용자·그룹을 Netskope에 동기화하고,
Google에서 사라진 항목은 Netskope에서도 삭제합니다.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import ssl
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httplib2
import requests
import urllib3
from dotenv import load_dotenv
from google.oauth2 import service_account
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class InsecureHTTPAdapter(HTTPAdapter):
    """urllib3는 session.verify=False여도 풀의 SSLContext를 재사용하는 경우가 있습니다."""

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        pool_kwargs["ssl_context"] = ctx
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        proxy_kwargs["ssl_context"] = ctx
        return super().proxy_manager_for(proxy, **proxy_kwargs)

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
]

ROOT = Path(__file__).resolve().parent
STATE_FILE = ROOT / "sync_state.json"
load_dotenv(ROOT / ".env")

log = logging.getLogger("provisioning")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name, "true" if default else "false").lower()
    return raw in {"1", "true", "yes", "y", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except ValueError:
        return default


def _csv_list(raw: str) -> list[str]:
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _resolve_path(raw: str) -> Path:
    path = Path(raw)
    return path if path.is_absolute() else ROOT / path


def normalize_tenant(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value:
        return value
    if not value.startswith("http"):
        value = f"https://{value}"
    host = value.split("://", 1)[-1]
    if "." not in host:
        value = f"{value}.goskope.com"
    return value.rstrip("/")


@dataclass
class Config:
    google_sa_key_file: Path
    google_admin_email: str
    google_customer: str
    google_domain: str
    netskope_tenant: str
    netskope_api_token: str
    target_groups: list[str] = field(default_factory=list)
    sync_users: str = "all"
    deprovision_missing: bool = True
    ssl_verify: bool = False
    dry_run: bool = False
    api_call_delay: float = 0.3
    users_only: bool = False
    groups_only: bool = False
    test_google: bool = False

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            google_sa_key_file=_resolve_path(
                _env("GOOGLE_SA_KEY_FILE", "service_account.json")
            ),
            google_admin_email=_env("GOOGLE_ADMIN_EMAIL"),
            google_customer=_env("GOOGLE_CUSTOMER", "my_customer"),
            google_domain=_env("GOOGLE_DOMAIN"),
            netskope_tenant=normalize_tenant(_env("NETSKOPE_TENANT")),
            netskope_api_token=_env("NETSKOPE_API_TOKEN"),
            target_groups=_csv_list(_env("TARGET_GROUPS")),
            sync_users=_env("SYNC_USERS", "all").lower() or "all",
            deprovision_missing=_env_bool("DEPROVISION_MISSING", True),
            ssl_verify=_env_bool("SSL_VERIFY", False),
            dry_run=_env_bool("DRY_RUN", False),
            api_call_delay=_env_float("API_CALL_DELAY", 0.3),
        )

    def validate(self, require_netskope: bool) -> None:
        missing = []
        if not self.google_admin_email:
            missing.append("GOOGLE_ADMIN_EMAIL")
        if require_netskope:
            if not self.netskope_tenant:
                missing.append("NETSKOPE_TENANT")
            if not self.netskope_api_token:
                missing.append("NETSKOPE_API_TOKEN")
        if missing:
            raise SystemExit(
                "필수 환경 변수가 없습니다: "
                + ", ".join(missing)
                + "\n.env 값을 채우세요."
            )
        if self.sync_users not in {"all", "members"}:
            raise SystemExit("SYNC_USERS 는 all 또는 members 여야 합니다.")
        if not self.google_sa_key_file.exists():
            raise SystemExit(
                f"Google Service Account JSON이 없습니다: {self.google_sa_key_file}"
            )


def setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def apply_ssl_settings(verify: bool) -> None:
    """Netskope SSL inspection 등 사설 인증서 체인에서 verify를 끕니다."""
    if verify:
        return
    ssl._create_default_https_context = ssl._create_unverified_context
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    log.warning("SSL 검증을 건너뜁니다 (SSL_VERIFY=false). Netskope SSL inspection 환경용입니다.")


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {"users": {}, "groups": {}}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"users": {}, "groups": {}}
    data.setdefault("users", {})
    data.setdefault("groups", {})
    return data


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


class GoogleDirectory:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        creds = service_account.Credentials.from_service_account_file(
            str(cfg.google_sa_key_file), scopes=GOOGLE_SCOPES
        )
        delegated = creds.with_subject(cfg.google_admin_email)
        http = httplib2.Http(
            timeout=60,
            disable_ssl_certificate_validation=not cfg.ssl_verify,
        )
        authorized = AuthorizedHttp(delegated, http=http)
        self.service = build(
            "admin", "directory_v1", http=authorized, cache_discovery=False
        )

    def _user_list_kwargs(self, deleted: bool = False) -> dict:
        kwargs: dict = {"maxResults": 500, "orderBy": "email", "projection": "full"}
        if self.cfg.google_domain:
            kwargs["domain"] = self.cfg.google_domain
        else:
            kwargs["customer"] = self.cfg.google_customer
        if deleted:
            kwargs["showDeleted"] = "true"
            kwargs.pop("orderBy", None)
        return kwargs

    def fetch_users(self) -> list[dict]:
        users: list[dict] = []
        page_token = None
        log.info("Admin SDK에서 사용자 목록 조회 중...")
        while True:
            result = self.service.users().list(
                pageToken=page_token, **self._user_list_kwargs()
            ).execute()
            users.extend(result.get("users", []))
            page_token = result.get("nextPageToken")
            if not page_token:
                break
            time.sleep(self.cfg.api_call_delay)
        log.info("  → 총 %s명의 사용자 조회 완료", len(users))
        return users

    def fetch_deleted_users(self) -> list[dict]:
        users: list[dict] = []
        page_token = None
        log.info("Admin SDK에서 삭제된 사용자 조회 중...")
        try:
            while True:
                result = self.service.users().list(
                    pageToken=page_token, **self._user_list_kwargs(deleted=True)
                ).execute()
                users.extend(result.get("users", []))
                page_token = result.get("nextPageToken")
                if not page_token:
                    break
                time.sleep(self.cfg.api_call_delay)
        except HttpError as exc:
            log.warning("삭제된 사용자 조회를 건너뜁니다: %s", exc)
            return []
        log.info("  → 삭제된 사용자 %s명", len(users))
        return users

    def fetch_user(self, email: str) -> Optional[dict]:
        try:
            return self.service.users().get(userKey=email, projection="full").execute()
        except HttpError as exc:
            if exc.resp.status == 404:
                return None
            raise

    def fetch_groups(self) -> list[dict]:
        if self.cfg.target_groups:
            groups = []
            log.info("지정 그룹 %s개 조회 중...", len(self.cfg.target_groups))
            for email in self.cfg.target_groups:
                try:
                    groups.append(self.service.groups().get(groupKey=email).execute())
                except HttpError as exc:
                    if exc.resp.status == 404:
                        log.warning("  Google에 없는 그룹 (삭제된 것으로 처리): %s", email)
                    else:
                        log.error("  그룹 조회 실패 [%s]: %s", email, exc)
            log.info("  → 존재하는 그룹 %s개", len(groups))
            return groups

        groups = []
        page_token = None
        log.info("Admin SDK에서 그룹 목록 조회 중...")
        list_kwargs: dict = {"maxResults": 200}
        if self.cfg.google_domain:
            list_kwargs["domain"] = self.cfg.google_domain
        else:
            list_kwargs["customer"] = self.cfg.google_customer
        while True:
            result = self.service.groups().list(pageToken=page_token, **list_kwargs).execute()
            groups.extend(result.get("groups", []))
            page_token = result.get("nextPageToken")
            if not page_token:
                break
            time.sleep(self.cfg.api_call_delay)
        log.info("  → 총 %s개 그룹 조회 완료", len(groups))
        return groups

    def fetch_group_members_flat(
        self,
        group_email: str,
        visited: Optional[set[str]] = None,
    ) -> set[str]:
        if visited is None:
            visited = set()
        key = group_email.lower()
        if key in visited:
            return set()
        visited.add(key)

        emails: set[str] = set()
        page_token = None
        while True:
            result = self.service.members().list(
                groupKey=group_email,
                includeDerivedMembership=True,
                maxResults=200,
                pageToken=page_token,
            ).execute()
            for member in result.get("members", []):
                member_email = (member.get("email") or "").lower()
                if not member_email:
                    continue
                if member.get("status") and member["status"] != "ACTIVE":
                    continue
                member_type = member.get("type", "")
                if member_type == "USER":
                    emails.add(member_email)
                elif member_type == "GROUP":
                    log.info("    └ 중첩 그룹 처리: %s", member_email)
                    emails.update(self.fetch_group_members_flat(member_email, visited))
            page_token = result.get("nextPageToken")
            if not page_token:
                break
            time.sleep(self.cfg.api_call_delay)
        return emails


class NetskopeScimClient:
    def __init__(self, tenant_url: str, api_token: str, dry_run: bool = False, ssl_verify: bool = False):
        self.base_url = f"{tenant_url.rstrip('/')}/api/v2/scim"
        self.dry_run = dry_run
        self.ssl_verify = ssl_verify
        self.headers = {
            "Netskope-Api-Token": api_token,
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.session = requests.Session()
        retry = Retry(
            total=5,
            connect=3,
            read=3,
            backoff_factor=1.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST", "PATCH", "PUT", "DELETE"}),
            respect_retry_after_header=True,
        )
        adapter = InsecureHTTPAdapter(max_retries=retry) if not ssl_verify else HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.verify = ssl_verify

    def _request(self, method: str, path: str, payload: dict | None = None, params: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        if self.dry_run and method != "GET":
            log.info("    [DRY-RUN] %s %s %s", method, path, json.dumps(payload or {}, ensure_ascii=False))
            return {"id": f"dry-run-{abs(hash(path)) % 10_000_000}"}

        resp = self.session.request(
            method,
            url,
            headers=self.headers,
            json=payload,
            params=params,
            timeout=60,
            verify=self.ssl_verify,
        )
        if resp.status_code not in (200, 201, 204):
            log.error("API 오류 [%s] %s %s: %s", resp.status_code, method, path, resp.text[:500])
        resp.raise_for_status()
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return {}

    def get_user_by_email(self, email: str) -> Optional[dict]:
        result = self._request("GET", "/Users", params={"filter": f'userName eq "{email}"'})
        resources = result.get("Resources") or []
        return resources[0] if resources else None

    def create_user(self, google_user: dict) -> dict:
        name = google_user.get("name") or {}
        email = google_user["primaryEmail"]
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": email,
            "externalId": google_user["id"],
            "displayName": name.get("fullName") or email,
            "name": {
                "givenName": name.get("givenName") or "",
                "familyName": name.get("familyName") or "",
            },
            "emails": [{"value": email, "primary": True, "type": "work"}],
            "active": not google_user.get("suspended", False),
        }
        log.info("    [CREATE USER] %s", email)
        try:
            created = self._request("POST", "/Users", payload=payload)
            if not created.get("id"):
                raise RuntimeError(f"SCIM create user 응답에 id가 없습니다: {email}")
            return created
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 409:
                existing = self.get_user_by_email(email)
                if existing:
                    self.update_user(existing["id"], google_user, existing)
                    return existing
            raise

    def update_user(self, scim_id: str, google_user: dict, existing: Optional[dict] = None) -> dict:
        name = google_user.get("name") or {}
        email = google_user["primaryEmail"]
        desired_active = not google_user.get("suspended", False)
        given = name.get("givenName") or ""
        family = name.get("familyName") or ""
        if existing:
            existing_name = existing.get("name") or {}
            if (
                bool(existing.get("active", True)) == desired_active
                and (existing_name.get("givenName") or "") == given
                and (existing_name.get("familyName") or "") == family
            ):
                log.info("    [SKIP USER] 변경 없음: %s", email)
                return existing
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "value": {
                    "active": desired_active,
                    "name": {"givenName": given, "familyName": family},
                },
            }],
        }
        log.info("    [UPDATE USER] %s (active=%s)", email, desired_active)
        return self._request("PATCH", f"/Users/{scim_id}", payload=payload)

    def delete_user(self, scim_id: str, label: str) -> None:
        log.info("    [DELETE USER] %s", label)
        self._request("DELETE", f"/Users/{scim_id}")

    def get_group_by_name(self, display_name: str) -> Optional[dict]:
        result = self._request("GET", "/Groups", params={"filter": f'displayName eq "{display_name}"'})
        resources = result.get("Resources") or []
        return resources[0] if resources else None

    def create_group(self, display_name: str, external_id: str, member_scim_ids: list[str]) -> dict:
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": display_name,
            "externalId": external_id,
            "members": [{"value": uid} for uid in member_scim_ids],
        }
        log.info("    [CREATE GROUP] %s (멤버 %s명)", display_name, len(member_scim_ids))
        try:
            return self._request("POST", "/Groups", payload=payload)
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 409:
                existing = self.get_group_by_name(display_name)
                if existing:
                    self.replace_group_members(existing["id"], member_scim_ids)
                    return existing
            raise

    def replace_group_members(self, scim_group_id: str, member_scim_ids: list[str]) -> dict:
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "members",
                "value": [{"value": uid} for uid in member_scim_ids],
            }],
        }
        log.info("    [UPDATE GROUP MEMBERS] group_id=%s (멤버 %s명)", scim_group_id, len(member_scim_ids))
        return self._request("PATCH", f"/Groups/{scim_group_id}", payload=payload)

    def delete_group(self, scim_id: str, label: str) -> None:
        log.info("    [DELETE GROUP] %s", label)
        self._request("DELETE", f"/Groups/{scim_id}")


@dataclass
class SyncStats:
    users_created: int = 0
    users_updated: int = 0
    users_skipped: int = 0
    users_deleted: int = 0
    users_failed: int = 0
    groups_created: int = 0
    groups_updated: int = 0
    groups_deleted: int = 0
    groups_failed: int = 0


def provision_users(
    ns: Optional[NetskopeScimClient],
    google_users: list[dict],
    cfg: Config,
    stats: SyncStats,
    state: dict,
) -> dict[str, str]:
    email_to_scim_id: dict[str, str] = {}
    log.info("=== [Phase 1] 사용자 프로비저닝 (%s명) ===", len(google_users))
    for g_user in google_users:
        email = (g_user.get("primaryEmail") or "").lower()
        if not email:
            stats.users_skipped += 1
            continue
        google_id = g_user["id"]
        if ns is None:
            log.info("    [PLAN USER] %s", email)
            email_to_scim_id[email] = f"plan-{email}"
            state["users"][google_id] = {"email": email, "scim_id": email_to_scim_id[email]}
            stats.users_created += 1
            continue
        try:
            existing = ns.get_user_by_email(email)
            if existing:
                ns.update_user(existing["id"], g_user, existing)
                scim_id = existing["id"]
                stats.users_updated += 1
            else:
                created = ns.create_user(g_user)
                scim_id = created["id"]
                stats.users_created += 1
            email_to_scim_id[email] = scim_id
            state["users"][google_id] = {"email": email, "scim_id": scim_id}
        except Exception:
            stats.users_failed += 1
            log.exception("  사용자 처리 실패: %s", email)
        time.sleep(cfg.api_call_delay)
    return email_to_scim_id


def provision_groups(
    directory: GoogleDirectory,
    ns: Optional[NetskopeScimClient],
    google_groups: list[dict],
    email_to_scim_id: dict[str, str],
    cfg: Config,
    stats: SyncStats,
    state: dict,
) -> None:
    log.info("=== [Phase 2] 그룹 프로비저닝 (%s개) ===", len(google_groups))
    for g_group in google_groups:
        group_email = (g_group.get("email") or "").lower()
        group_name = g_group.get("name") or group_email
        group_id = g_group["id"]
        log.info("  그룹 처리 중: %s (%s)", group_name, group_email)
        try:
            member_emails = directory.fetch_group_members_flat(g_group["email"])
            member_scim_ids = [email_to_scim_id[e] for e in member_emails if e in email_to_scim_id]
            skipped = len(member_emails) - len(member_scim_ids)
            if skipped:
                log.warning("    → %s명의 멤버가 Netskope 매핑에 없어 제외됨", skipped)
            if ns is None:
                log.info("    [PLAN GROUP] %s 멤버 %s명", group_name, len(member_emails))
                state["groups"][group_id] = {
                    "email": group_email,
                    "name": group_name,
                    "scim_id": f"plan-{group_id}",
                }
                stats.groups_created += 1
                continue

            existing_group = ns.get_group_by_name(group_name)
            if existing_group is None and group_name != group_email:
                existing_group = ns.get_group_by_name(group_email)
            if existing_group:
                ns.replace_group_members(existing_group["id"], member_scim_ids)
                scim_id = existing_group["id"]
                stats.groups_updated += 1
            else:
                created = ns.create_group(group_name, group_id, member_scim_ids)
                scim_id = created.get("id") or ""
                stats.groups_created += 1
            state["groups"][group_id] = {
                "email": group_email,
                "name": group_name,
                "scim_id": scim_id,
            }
        except Exception:
            stats.groups_failed += 1
            log.exception("  그룹 처리 실패: %s", group_email)
        time.sleep(cfg.api_call_delay)


def deprovision_users(
    ns: Optional[NetskopeScimClient],
    live_google_ids: set[str],
    deleted_google_ids: set[str],
    state: dict,
    stats: SyncStats,
    cfg: Config,
) -> None:
    if not cfg.deprovision_missing:
        return
    log.info("=== [Phase 3] 사용자 삭제 동기화 ===")
    for google_id, info in list(state["users"].items()):
        gone = google_id not in live_google_ids or google_id in deleted_google_ids
        if not gone:
            continue
        label = info.get("email") or google_id
        scim_id = info.get("scim_id")
        try:
            if ns and scim_id and not str(scim_id).startswith("plan-"):
                ns.delete_user(scim_id, label)
            else:
                log.info("    [PLAN DELETE USER] %s", label)
            del state["users"][google_id]
            stats.users_deleted += 1
        except Exception:
            stats.users_failed += 1
            log.exception("  사용자 삭제 실패: %s", label)
        time.sleep(cfg.api_call_delay)


def deprovision_groups(
    ns: Optional[NetskopeScimClient],
    live_google_ids: set[str],
    google_groups_fetched: bool,
    state: dict,
    stats: SyncStats,
    cfg: Config,
) -> None:
    if not cfg.deprovision_missing or not google_groups_fetched:
        return
    if not live_google_ids and not cfg.target_groups:
        log.warning("Google 그룹이 0개입니다. 오인 삭제를 막기 위해 그룹 deprovision을 건너뜁니다.")
        return
    log.info("=== [Phase 3] 그룹 삭제 동기화 ===")
    for google_id, info in list(state["groups"].items()):
        if google_id in live_google_ids:
            continue
        label = info.get("name") or info.get("email") or google_id
        scim_id = info.get("scim_id")
        try:
            if ns and scim_id and not str(scim_id).startswith("plan-"):
                ns.delete_group(scim_id, label)
            else:
                log.info("    [PLAN DELETE GROUP] %s", label)
            del state["groups"][google_id]
            stats.groups_deleted += 1
        except Exception:
            stats.groups_failed += 1
            log.exception("  그룹 삭제 실패: %s", label)
        time.sleep(cfg.api_call_delay)


def collect_member_users(directory: GoogleDirectory, google_groups: list[dict]) -> list[dict]:
    emails: set[str] = set()
    for g_group in google_groups:
        emails.update(directory.fetch_group_members_flat(g_group["email"]))
    users: list[dict] = []
    log.info("그룹 멤버 %s명의 Admin SDK 프로필 조회 중...", len(emails))
    for email in sorted(emails):
        user = directory.fetch_user(email)
        if user:
            users.append(user)
        time.sleep(directory.cfg.api_call_delay)
    return users


def test_google(directory: GoogleDirectory) -> int:
    users = directory.fetch_users()
    groups = directory.fetch_groups()
    log.info("Admin SDK 테스트 성공: 사용자 %s명, 그룹 %s개", len(users), len(groups))
    for user in users[:5]:
        log.info("  user: %s", user.get("primaryEmail"))
    for group in groups[:5]:
        log.info("  group: %s <%s>", group.get("name"), group.get("email"))
    return 0


def provision(cfg: Config) -> SyncStats:
    directory = GoogleDirectory(cfg)
    ns = None
    if cfg.netskope_api_token:
        ns = NetskopeScimClient(
            cfg.netskope_tenant,
            cfg.netskope_api_token,
            dry_run=cfg.dry_run,
            ssl_verify=cfg.ssl_verify,
        )
    elif cfg.dry_run:
        log.info("NETSKOPE_API_TOKEN 없음 → Google 조회 계획만 출력합니다.")

    stats = SyncStats()
    state = load_state()
    google_groups: list[dict] = []
    groups_fetched = False

    if not cfg.users_only:
        google_groups = directory.fetch_groups()
        groups_fetched = True

    if not cfg.groups_only:
        if cfg.sync_users == "members":
            if not google_groups:
                google_groups = directory.fetch_groups()
                groups_fetched = True
            google_users = collect_member_users(directory, google_groups)
        else:
            google_users = directory.fetch_users()
        email_to_scim_id = provision_users(ns, google_users, cfg, stats, state)
        live_user_ids = {u["id"] for u in google_users if u.get("id")}
        deleted_ids = {u["id"] for u in directory.fetch_deleted_users() if u.get("id")}
        if live_user_ids or cfg.sync_users == "members":
            deprovision_users(ns, live_user_ids, deleted_ids, state, stats, cfg)
        else:
            log.warning("Google 사용자가 0명입니다. 사용자 deprovision을 건너뜁니다.")
    else:
        email_to_scim_id = {}
        log.info("=== --groups-only: 기존 Netskope 사용자 조회 ===")
        source_groups = google_groups or directory.fetch_groups()
        groups_fetched = True
        member_emails: set[str] = set()
        for g in source_groups:
            member_emails.update(directory.fetch_group_members_flat(g["email"]))
        for email in sorted(member_emails):
            if ns is None:
                continue
            existing = ns.get_user_by_email(email)
            if existing:
                email_to_scim_id[email] = existing["id"]
            else:
                log.warning("  Netskope에 없는 멤버: %s", email)
            time.sleep(cfg.api_call_delay)

    if not cfg.users_only:
        provision_groups(directory, ns, google_groups, email_to_scim_id, cfg, stats, state)
        live_group_ids = {g["id"] for g in google_groups if g.get("id")}
        deprovision_groups(ns, live_group_ids, groups_fetched, state, stats, cfg)

    if not cfg.dry_run:
        save_state(state)
    else:
        log.info("DRY-RUN: sync_state.json 을 갱신하지 않습니다.")

    log.info("=== 프로비저닝 완료%s ===", " (DRY-RUN)" if cfg.dry_run or ns is None else "")
    log.info(
        "사용자 created=%s updated=%s deleted=%s failed=%s | "
        "그룹 created=%s updated=%s deleted=%s failed=%s",
        stats.users_created, stats.users_updated, stats.users_deleted, stats.users_failed,
        stats.groups_created, stats.groups_updated, stats.groups_deleted, stats.groups_failed,
    )
    return stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Google Admin SDK 사용자/그룹을 Netskope SCIM으로 동기화합니다."
    )
    parser.add_argument("--dry-run", action="store_true", help="Netskope에 쓰지 않고 계획만 출력")
    parser.add_argument("--test-google", action="store_true", help="Admin SDK 연결만 확인하고 종료")
    parser.add_argument("--users-only", action="store_true")
    parser.add_argument("--groups-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    setup_logging()
    args = parse_args()
    cfg = Config.from_env()
    if args.dry_run:
        cfg.dry_run = True
    cfg.users_only = args.users_only
    cfg.groups_only = args.groups_only
    cfg.test_google = args.test_google
    if cfg.users_only and cfg.groups_only:
        log.error("--users-only 와 --groups-only 는 함께 쓸 수 없습니다.")
        return 2

    require_netskope = not cfg.test_google and not cfg.dry_run
    cfg.validate(require_netskope=require_netskope)
    apply_ssl_settings(cfg.ssl_verify)

    if cfg.test_google:
        return test_google(GoogleDirectory(cfg))

    if cfg.dry_run:
        log.info("DRY-RUN 모드: Netskope에 변경을 쓰지 않습니다.")
    stats = provision(cfg)
    if stats.users_failed or stats.groups_failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
