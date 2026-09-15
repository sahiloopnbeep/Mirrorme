```javascript
export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const body = req.body || {};
        const email = body.email;
        const access_key = body.access_key;

        if (!email || !access_key) {
            return res.status(400).json({ error: 'Email and Access PIN are required' });
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const normalizedKey = String(access_key).trim();

        const url =
            process.env.SUPABASE_URL +
            '/rest/v1/member_calculations?select=email,access_key&email=eq.' +
            encodeURIComponent(normalizedEmail) +
            '&access_key=eq.' +
            encodeURIComponent(normalizedKey) +
            '&limit=1';

        const response = await fetch(url, {
            headers: {
                apikey: process.env.SUPABASESERVICEROLEKEY,
                Authorization: 'Bearer ' + process.env.SUPABASESERVICEROLEKEY
            }
        });

        if (!response.ok) {
            return res.status(500).json({ error: 'Unable to verify member details' });
        }

        const members = await response.json();

        if (!members.length) {
            return res.status(401).json({ error: 'Invalid email or Access PIN' });
        }

        const payload = {
            email: normalizedEmail,
            exp: Date.now() + 8 * 60 * 60 * 1000
        };

        const payloadString =
            Buffer.from(JSON.stringify(payload)).toString('base64url');

        const crypto = await import('node:crypto');

        const signature = crypto
            .createHmac('sha256', process.env.MIRROR_ME_SESSION_SECRET)
            .update(payloadString)
            .digest('base64url');

        const session = payloadString + '.' + signature;

        res.setHeader(
            'Set-Cookie',
            'mirror_me_session=' +
            session +
            '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800'
        );

        return res.status(200).json({ success: true });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Server error' });
    }
}
```
