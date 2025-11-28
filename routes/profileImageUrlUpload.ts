/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'


const allowedProtocols = ['http:', 'https:'];
const allowedDomains = ['trusted-domain.com', 'cdn.example.com'];

function validateUrl(url: string): boolean {
  try {
    const parsedUrl = new URL(url);
    
    // Validar protocolo
    if (!allowedProtocols.includes(parsedUrl.protocol)) {
      return false;
    }
    
    // Bloquear IPs privados e localhost
    const hostname = parsedUrl.hostname;
    if (hostname === 'localhost' || 
        hostname.startsWith('127.') || 
        hostname.startsWith('10.') ||
        hostname.startsWith('192.168.') ||
        hostname.startsWith('172.')) {
      return false;
    }
    
    // Opcional: whitelist de domínios
    // return allowedDomains.some(domain => hostname.endsWith(domain));
    
    return true;
  } catch {
    return false;
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) {
        req.app.locals.abused_ssrf_bug = true
      }
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          // Validação do host antes de fazer o fetch
          let hostname: string
          try {
            hostname = new URL(url).hostname
          } catch (e) {
            return res.status(400).send('Invalid URL format')
          }
          if (!ALLOWED_HOSTS.includes(hostname)) {
            return res.status(403).send('Host not allowed')
          }

          if (!validateUrl(url)) {
            throw new Error('Invalid or forbidden URL');
          }

          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(
            url.split('.').slice(-1)[0].toLowerCase()
          ) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(
            `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`,
            { flags: 'w' }
          )
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(
            async (user: UserModel | null) => {
              return await user?.update({
                profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
              })
            }
          ).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(
              `Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`
            )
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
