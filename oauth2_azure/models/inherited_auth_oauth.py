# -*- coding: utf-8 -*-

from odoo import fields, models


class AuthOAuthProvider(models.Model):
    _inherit = 'auth.oauth.provider'

    client_secret = fields.Char(
        string='Client Secret',
    )
    response_type = fields.Selection(
        selection=[
            ('token', 'Token'),
            ('code', 'Code')
        ],
        default='token',
        required=True,
    )
