import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// Allowlist de hosts para imagens de perfil
const ALLOWED_IMAGE_HOSTS = [
  'www.gravatar.com',
  'secure.gravatar.com'
]

function parseAndValidateImageUrl(urlString: string): URL | null {
  try {
    const url = new URL(urlString)

    // Só permitir HTTPS
    if (url.protocol !== 'https:') {
      return null
    }

    // Host tem de estar na allowlist
    if (!ALLOWED_IMAGE_HOSTS.includes(url.hostname)) {
      return null
    }

    return url
  } catch {
    return null
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const imageUrl = String(req.body.imageUrl)

      if (imageUrl.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) {
        req.app.locals.abused_ssrf_bug = true
      }

      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }

      const safeUrl = parseAndValidateImageUrl(imageUrl)
      if (!safeUrl) {
        return res.status(400).json({ error: 'Invalid or forbidden image URL' })
      }

      try {
        const response = await fetch(safeUrl.toString())
        if (!response.ok || !response.body) {
          throw new Error('url returned a non-OK status code or an empty body')
        }

        const contentType = response.headers.get('content-type') || ''
        if (!contentType.startsWith('image/')) {
          throw new Error('URL does not point to an image resource')
        }

        const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(
          safeUrl.pathname.split('.').slice(-1)[0].toLowerCase()
        ) ? safeUrl.pathname.split('.').slice(-1)[0].toLowerCase() : 'jpg'

        const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
        const fileStream = fs.createWriteStream(filePath, { flags: 'w' })
        await finished(Readable.fromWeb(response.body as any).pipe(fileStream))

        await UserModel.findByPk(loggedInUser.data.id)
          .then(async (user: UserModel | null) => {
            return await user?.update({
              profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
            })
          })
          .catch((error: Error) => { next(error) })
      } catch (error) {
        logger.warn(
          `Error retrieving user profile image: ${utils.getErrorMessage(error)}; falling back to default avatar`
        )
        try {
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({
            profileImage: '/assets/public/images/uploads/defaultAvatar.jpg'
          })
        } catch (err) {
          next(err)
          return
        }
      }
    }

    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
