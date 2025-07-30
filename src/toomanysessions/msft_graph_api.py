from dataclasses import dataclass
from typing import Any, Optional, List

import httpx
from loguru import logger as log


@dataclass
class Me:
    businessPhones: Any
    displayName: str
    givenName: str
    jobTitle: str
    mail: str
    mobilePhone: Any
    officeLocation: Any
    preferredLanguage: Any
    surname: str
    userPrincipalName: Any
    id: str

@dataclass
class Organization:
   id: str
   deletedDateTime: Any
   businessPhones: Any
   city: Any
   country: Any
   countryLetterCode: Any
   createdDateTime: Any
   defaultUsageLocation: Any
   displayName: str
   isMultipleDataLocationsForServicesEnabled: Any
   marketingNotificationEmails: Any
   onPremisesLastSyncDateTime: Any
   onPremisesSyncEnabled: Any
   partnerTenantType: Any
   postalCode: Any
   preferredLanguage: Any
   securityComplianceNotificationMails: Any
   securityComplianceNotificationPhones: Any
   state: Any
   street: Any
   technicalNotificationMails: Any
   tenantType: str
   directorySizeQuota: Any
   privacyProfile: Any
   assignedPlans: Any
   onPremisesSyncStatus: Any
   provisionedPlans: Any
   verifiedDomains: Any


class GraphAPI:
    def __init__(self, token: str, version: str = "v1.0"):
        self.token: str = token
        self.version = version.strip("/")
        self.base_url = f"https://graph.microsoft.com/{self.version}"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def __repr__(self):
        return f"[GraphAPI.{self.token[:4]}"

    @property
    async def me(self):
        info: dict = await self.request(
            method="get",
            resource="me"
        )
        del info['@odata.context']
        return Me(**info)

    @property
    async def organization(self):
        """Get user's organization/tenant info from Graph API"""
        info = await self.request(
            "GET",
            "organization"
        )
        info = info["value"][0]
        inst = Organization(**info)
        log.debug(f"{self}: Got user's organizational info:\n  - org={inst}")
        return inst

    async def request(self, method, resource, query_parameters=None, headers=None, json_body=None):
        url = f"{self.base_url}/{resource}"

        request_headers = self.headers.copy()
        if headers:
            request_headers.update(headers)

        params = {}
        if query_parameters:
            if isinstance(query_parameters, str):
                for param in query_parameters.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        params[key] = value
            else:
                params = query_parameters

        log.info(f"{self}: Sending {method.upper()} request to: {url}")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.request(
                    method=method.upper(),
                    url=url,
                    headers=request_headers,
                    params=params,
                    json=json_body
                )

                if not response.is_success:
                    log.error(f"{self}: Error {response.status_code}: {response.text}")
                    return None

                return response.json()

        except Exception as e:
            log.exception(f"{self}: Request failed: {e}")
            return None
