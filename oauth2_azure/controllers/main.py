# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo.http import request
from odoo.addons.auth_oauth.controllers.main import OAuthLogin as Home

import json

import werkzeug.urls
import werkzeug.utils


#----------------------------------------------------------
# Controller
# Extend list_providers to have different response_type
#----------------------------------------------------------
class OAuthLogin(Home):
    def list_providers(self):
        providers = super().list_providers()
        for provider in providers:
            prov = request.env['auth.oauth.provider'].sudo().search([('id', '=', provider['id'])])
            return_url = request.httprequest.url_root + 'auth_oauth/signin'
            state = self.get_state(provider)
            provider['response_type'] = prov['response_type']
            params = dict(
                response_type=prov['response_type'],
                client_id=provider['client_id'],
                redirect_uri=return_url,
                scope=provider['scope'],
                state=json.dumps(state),
            )
            provider['auth_link'] = "%s?%s" % (provider['auth_endpoint'], werkzeug.url_encode(params))
        return providers
