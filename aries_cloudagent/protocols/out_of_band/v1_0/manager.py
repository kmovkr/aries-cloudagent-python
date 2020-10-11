"""Classes to manage connections."""

import logging
import json

from ....connections.models.connection_record import ConnectionRecord
from ....config.injection_context import InjectionContext
from ....core.error import BaseError
from ....ledger.base import BaseLedger
from ....wallet.util import did_key_to_naked, naked_to_did_key, b64_to_str

from ...connections.v1_0.manager import ConnectionManager
from ...present_proof.v1_0.manager import PresentationManager
from ...connections.v1_0.messages.connection_invitation import ConnectionInvitation
from ...didcomm_prefix import DIDCommPrefix
from ...issue_credential.v1_0.models.credential_exchange import V10CredentialExchange
from ...present_proof.v1_0.models.presentation_exchange import V10PresentationExchange

from .models.invitation import Invitation as InvitationModel
from .messages.invitation import Invitation as InvitationMessage
from .messages.service import Service as ServiceMessage


HS_PROTO_CONN_INVI = "connections/1.0/invitation"


class OutOfBandManagerError(BaseError):
    """Out of band error."""


class OutOfBandManagerNotImplementedError(BaseError):
    """Out of band error for unimplemented functionality."""


class OutOfBandManager:
    """Class for managing out of band messages."""

    def __init__(self, context: InjectionContext):
        """
        Initialize a OutOfBandManager.

        Args:
            context: The context for this out of band manager
        """
        self._context = context
        self._logger = logging.getLogger(__name__)

    @property
    def context(self) -> InjectionContext:
        """
        Accessor for the current injection context.

        Returns:
            The injection context for this connection manager

        """
        return self._context

    async def create_invitation(
        self,
        my_label: str = None,
        my_endpoint: str = None,
        use_public_did: bool = False,
        include_handshake: bool = False,
        multi_use: bool = False,
        attachments: list = None,
    ) -> InvitationModel:
        """
        Generate new out of band invitation.

        This interaction represents an out-of-band communication channel. The resulting
        message is expected to be used to bootstrap the secure peer-to-peer
        communication channel.

        Args:
            my_label: label for this connection
            my_endpoint: endpoint where other party can reach me
            public: set to create an invitation from the public DID
            multi_use: set to True to create an invitation for multiple use
            attachments: list of dicts in the form of
                {"id": "jh5k23j5gh2123", "type": "credential-offer"}

        Returns:
            A tuple of the new `InvitationModel` and out of band `InvitationMessage`
            instances

        """

        connection_mgr = ConnectionManager(self.context)
        (connection, connection_invitation) = await connection_mgr.create_invitation(
            my_label=my_label,
            my_endpoint=my_endpoint,
            auto_accept=True,
            public=use_public_did,
            multi_use=multi_use,
        )
        # wallet: BaseWallet = await self.context.inject(BaseWallet)

        if not my_label:
            my_label = self.context.settings.get("default_label")
        # if not my_endpoint:
        #     my_endpoint = self.context.settings.get("default_endpoint")

        message_attachments = []
        if attachments:
            for attachment in attachments:
                attachment_type = attachment.get("type")
                if attachment_type == "credential-offer":
                    instance_id = attachment["id"]
                    model = await V10CredentialExchange.retrieve_by_id(
                        self.context, instance_id
                    )
                    # Wrap as attachment decorators
                    message_attachments.append(
                        InvitationMessage.wrap_message(model.credential_offer_dict)
                    )
                elif attachment_type == "present-proof":
                    instance_id = attachment["id"]
                    model = await V10PresentationExchange.retrieve_by_id(
                        self.context, instance_id
                    )
                    # Wrap as attachment decorators
                    message_attachments.append(
                        InvitationMessage.wrap_message(model.presentation_request_dict)
                    )
                else:
                    raise OutOfBandManagerError(
                        f"Unknown attachment type: {attachment_type}"
                    )

        # We plug into existing connection structure during migration phase
        if use_public_did:
            # service = (await wallet.get_public_did()).did
            service = connection_invitation.did
        else:
            # connection_key = await wallet.create_signing_key()
            # service = ServiceMessage(
            #     id="#inline",
            #     type="did-communication",
            #     recipient_keys=[connection_key.verkey],
            #     routing_keys=[],
            #     service_endpoint=my_endpoint,
            # )
            service = ServiceMessage(
                _id="#inline",
                _type="did-communication",
                recipient_keys=[
                    naked_to_did_key(key)
                    for key in connection_invitation.recipient_keys or []
                ],
                routing_keys=[
                    naked_to_did_key(key)
                    for key in connection_invitation.routing_keys or []
                ],
                service_endpoint=connection_invitation.endpoint,
            ).validate()

        handshake_protocols = []
        if include_handshake:
            # handshake_protocols.append("https://didcomm.org/connections/1.0")
            # handshake_protocols.append("https://didcomm.org/didexchange/1.0")
            handshake_protocols.extend(
                pfx.qualify(HS_PROTO_CONN_INVI) for pfx in DIDCommPrefix
            )

        invitation_message = InvitationMessage(
            label=my_label,
            service=[service],
            request_attach=message_attachments,
            handshake_protocols=handshake_protocols,
        ).validate()

        # Create record
        invitation_model = InvitationModel(
            state=InvitationModel.STATE_INITIAL,
            invitation=invitation_message.serialize(),
        )

        await invitation_model.save(self.context, reason="Created new invitation")

        return invitation_model

    async def receive_invitation(
        self, invitation: InvitationMessage
    ) -> ConnectionRecord:
        """Receive an out of band invitation message."""

        ledger: BaseLedger = await self.context.inject(BaseLedger)

        # New message format
        invitation_message = InvitationMessage.deserialize(invitation)
        print("-" * 10, "invitation_message", "-" * 10)
        print("invitation_message", invitation_message)

        # Convert to old format and pass to relevant manager
        # The following logic adheres to Aries RFC 0496

        # There must be exactly 1 service entry
        if (
            len(invitation_message.service_blocks)
            + len(invitation_message.service_dids)
            != 1
        ):
            raise OutOfBandManagerError("service array must have exactly one element")

        # Get the single service item
        if invitation_message.service_blocks:
            service = invitation_message.service_blocks[0]

        else:
            # If it's in the did format, we need to convert to a full service block
            service_did = invitation_message.service_dids[0]
            print("-" * 10, "service_did", "-" * 10)
            print(service_did)
            async with ledger:
                verkey = await ledger.get_key_for_did(service_did)
                did_key = naked_to_did_key(verkey)
                endpoint = await ledger.get_endpoint_for_did(service_did)
            print("-" * 10, "did_", "-" * 10)
            print(verkey, did_key, endpoint)
            service = ServiceMessage.deserialize(
                {
                    "id": "#inline",
                    "type": "did-communication",
                    "recipientKeys": [did_key],
                    "routingKeys": [],
                    "serviceEndpoint": endpoint,
                }
            )
            print("-" * 10, "serivce", "-" * 10)
            print(service)

        unq_handshake_protos = {
            DIDCommPrefix.unqualify(proto)
            for proto in invitation_message.handshake_protocols
        }

        # If we are dealing with an invitation
        if unq_handshake_protos == {HS_PROTO_CONN_INVI}:
            if len(invitation_message.request_attach) != 0:
                raise OutOfBandManagerError(
                    "request block must be empty for invitation message type."
                )

            # Transform back to 'naked' verkey
            service.recipient_keys = [
                did_key_to_naked(key) for key in service.recipient_keys or []
            ]
            service.routing_keys = [
                did_key_to_naked(key) for key in service.routing_keys
            ] or []

            # Convert to the old message format
            connection_invitation = ConnectionInvitation.deserialize(
                {
                    "@id": invitation_message._id,
                    "@type": DIDCommPrefix.qualify_current(HS_PROTO_CONN_INVI),
                    "label": invitation_message.label,
                    "recipientKeys": service.recipient_keys,
                    "serviceEndpoint": service.service_endpoint,
                    "routingKeys": service.routing_keys,
                }
            )

            print("-" * 10, "connection_invitation", "-" * 10)
            print(connection_invitation)

            connection_mgr = ConnectionManager(self.context)
            connection = await connection_mgr.receive_invitation(
                connection_invitation, auto_accept=True
            )

        elif len(
            invitation_message.request_attach
        ) == 1 and invitation_message.request_attach[0].data.json["@type"] in [
            pfx.qualify("present-proof/1.0/request-presentation")
            for pfx in DIDCommPrefix
        ]:
            # raise OutOfBandManagerNotImplementedError(
            #     f"{invitation_message.request_attach[0].data.json['@type']} "
            #     "request type not implemented."
            # )
            service.recipient_keys = [
                did_key_to_naked(key) for key in service.recipient_keys or []
            ]
            print("-" * 10, "service.recipient_keys", "-" * 10)
            print(service.recipient_keys)
            service.routing_keys = [
                did_key_to_naked(key) for key in service.routing_keys
            ] or []

            # Convert to the old message format
            connection_invitation = ConnectionInvitation.deserialize(
                {
                    "@id": invitation_message._id,
                    "@type": DIDCommPrefix.qualify_current(HS_PROTO_CONN_INVI),
                    "label": invitation_message.label,
                    "recipientKeys": service.recipient_keys,
                    "serviceEndpoint": service.service_endpoint,
                    "routingKeys": service.routing_keys,
                }
            )

            print("-" * 10, "connection_invitation", "-" * 10)
            print(connection_invitation)

            connection_mgr = ConnectionManager(self.context)
            connection = await connection_mgr.receive_invitation(
                connection_invitation, auto_accept=True
            )
            print("-"*10, "connection_id", "-"*10)
            print(connection._id)

            print("-"*10, "connection", "-"*10)
            print(connection)

            request_attach = invitation_message.request_attach
            print("-" * 10, "request_attach", "-" * 10)
            print(request_attach)

            request_attach_data = request_attach[0].data.json_
            print("-" * 10, "request_attach_data", "-" * 10)
            print(request_attach_data)

            proof_message = V10PresentationExchange(
                thread_id=request_attach_data["@id"],
                state=V10PresentationExchange.STATE_REQUEST_RECEIVED,
                presentation_request=json.loads(b64_to_str(
                    request_attach_data["request_presentations~attach"][0]["data"]["base64"])),
                connection_id=connection._id,
            )

            print("-" * 10, "proof_message", "-" * 10)
            print("proof_message", proof_message)
            presentation_manager = PresentationManager(self.context)
            pre_ex_id = await presentation_manager.receive_request(
                presentation_exchange_record=proof_message)
            print("-" * 10, "pre_ex_id", "-" * 10)
            print(pre_ex_id)

            return pre_ex_id

            print([
                pfx.qualify("present-proof/1.0/request-presentation")
                for pfx in DIDCommPrefix
            ])
            raise OutOfBandManagerError("Invalid request type")

        return connection
