# -*- coding: utf-8 -*-

import logging

from odoo import api, fields, models

_logger = logging.getLogger(__name__)


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    auth_oauth_microsoft_enabled = fields.Boolean(
        string='Allow users to sign in with Microsoft'
    )
    auth_oauth_microsoft_client_id = fields.Char(
        string='Microsoft Client ID'
    )
    auth_oauth_microsoft_client_secret = fields.Char(
        string='Microsoft Client Secret'
    )

    @api.model
    def get_values(self):
        res = super(ResConfigSettings, self).get_values()
        microsoft_provider = self.env.ref('oauth2_azure.provider_microsoft', False)
        res.update(
            auth_oauth_microsoft_enabled=microsoft_provider.enabled,
            auth_oauth_microsoft_client_id=microsoft_provider.client_id,
            auth_oauth_microsoft_client_secret=microsoft_provider.client_secret,
        )
        return res

    def set_values(self):
        super(ResConfigSettings, self).set_values()
        microsoft_provider = self.env.ref('oauth2_azure.provider_microsoft', False)
        microsoft_provider.write({
            'enabled': self.auth_oauth_microsoft_enabled,
            'client_id': self.auth_oauth_microsoft_client_id,
            'client_secret': self.auth_oauth_microsoft_client_secret,
        })
