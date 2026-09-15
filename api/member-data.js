```javascript
import crypto from 'node:crypto';

export default async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const cookies = req.headers.cookie || '';
        const match = cookies.match(/(?:^|;\s*)mirror_me_session=([^;]+)/);

        if (!match) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const session = decodeURIComponent(match[1]);
        const parts = session.split('.');

        if (parts.length !== 2) {
            return res.status(401).json({ error: 'Invalid session' });
        }

        const [payloadString, signature] = parts;

        const expectedSignature = crypto
            .createHmac('sha256', process.env.MIRROR_ME_SESSION_SECRET)
            .update(payloadString)
            .digest('base64url');

        if (
            !crypto.timingSafeEqual(
                Buffer.from(signature),
                Buffer.from(expectedSignature)
            )
        ) {
            return res.status(401).json({ error: 'Invalid session' });
        }

        const payload = JSON.parse(
            Buffer.from(payloadString, 'base64url').toString('utf8')
        );

        if (!payload.email || !payload.exp || Date.now() > payload.exp) {
            return res.status(401).json({ error: 'Session expired' });
        }

        const response = await fetch(
            `${process.env.SUPABASE_URL}/rest/v1/member_calculations?select=*&email=eq.${encodeURIComponent(payload.email)}&limit=1`,
            {
                headers: {
                    apikey: process.env.SUPABASESERVICEROLEKEY,
                    Authorization: `Bearer ${process.env.SUPABASESERVICEROLEKEY}`
                }
            }
        );

        if (!response.ok) {
            return res.status(500).json({ error: 'Unable to retrieve member data' });
        }

        const members = await response.json();

        if (!members.length) {
            return res.status(404).json({ error: 'Member data not found' });
        }

        return res.status(200).json(members[0]);
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Server error' });
    }
}
```
