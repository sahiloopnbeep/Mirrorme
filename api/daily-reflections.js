
const crypto = require('node:crypto');

const FIELDS = [
    'well_being',
    'sleep_quality',
    'active_days',
    'physical_energy',
    'diet_quality',
    'food_confidence'
];

const COOKIE_NAME = 'mirror_me_session';
const TIMEOUT_MS = 10000;

function respond(res, status, data) {
    return res.status(status).json(data);
}

function parseJson(value) {
    if (typeof value === 'object' && value !== null) {
        return value;
    }

    if (typeof value !== 'string') {
        throw new Error('Invalid JSON input');
    }

    return JSON.parse(value);
}

function isValidDate(value) {
    if (
        typeof value !== 'string' ||
        !/^\d{4}-\d{2}-\d{2}$/.test(value)
    ) {
        return false;
    }

    const date = new Date(value + 'T00:00:00.000Z');

    return (
        !Number.isNaN(date.getTime()) &&
        date.toISOString().slice(0, 10) === value
    );
}

function isAfterDate(value, referenceDate) {
    return value > referenceDate;
}

function getSessionEmail(req) {
    const cookieHeader = req.headers.cookie || '';

    const cookie = cookieHeader
        .split(';')
        .map(item => item.trim())
        .find(item => item.startsWith(COOKIE_NAME + '='));

    if (!cookie) {
        throw Object.assign(
            new Error('Not authenticated'),
            { status: 401 }
        );
    }

    const session = cookie.substring(
        COOKIE_NAME.length + 1
    );

    const parts = session.split('.');

    if (parts.length !== 2) {
        throw Object.assign(
            new Error('Invalid session'),
            { status: 401 }
        );
    }

    const [payloadString, receivedSignature] = parts;

    const secret = process.env.M_SESSION_SECRET;

    if (!secret) {
        throw Object.assign(
            new Error('Server configuration error'),
            { status: 500 }
        );
    }

    const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(payloadString)
        .digest('base64url');

    const receivedBuffer = Buffer.from(receivedSignature);
    const expectedBuffer = Buffer.from(expectedSignature);

    if (
        receivedBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(
            receivedBuffer,
            expectedBuffer
        )
    ) {
        throw Object.assign(
            new Error('Invalid session'),
            { status: 401 }
        );
    }

    let payload;

    try {
        payload = JSON.parse(
            Buffer.from(payloadString, 'base64url')
                .toString('utf8')
        );
    } catch {
        throw Object.assign(
            new Error('Invalid session data'),
            { status: 401 }
        );
    }

    if (
        typeof payload.email !== 'string' ||
        !payload.email.trim() ||
        !Number.isFinite(Number(payload.exp)) ||
        Number(payload.exp) <= Date.now()
    ) {
        throw Object.assign(
            new Error('Session expired or invalid'),
            { status: 401 }
        );
    }

    return payload.email.trim().toLowerCase();
}

function getSupabaseConfig() {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASESERVICEROLEKEY;

    if (!url || !key) {
        throw Object.assign(
            new Error('Server configuration error'),
            { status: 500 }
        );
    }

    return {
        url: url.replace(/\/$/, ''),
        headers: {
            apikey: key,
            Authorization: 'Bearer ' + key
        }
    };
}

async function fetchJson(url, options = {}) {
    const controller = new AbortController();

    const timeout = setTimeout(
        () => controller.abort(),
        TIMEOUT_MS
    );

    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });

        const responseText = await response.text();

        let data = null;

        if (responseText) {
            try {
                data = JSON.parse(responseText);
            } catch {
                throw Object.assign(
                    new Error('Invalid response from database'),
                    { status: 502 }
                );
            }
        }

        if (!response.ok) {
            console.error(
                'Supabase request failed:',
                response.status,
                data
            );

            throw Object.assign(
                new Error('Database request failed'),
                { status: 502 }
            );
        }

        return data;

    } catch (error) {
        if (error.name === 'AbortError') {
            throw Object.assign(
                new Error('Database request timed out'),
                { status: 504 }
            );
        }

        throw error;

    } finally {
        clearTimeout(timeout);
    }
}

async function getMemberId(email, config) {
    const url =
        config.url +
        '/rest/v1/member_calculations?select=id&email=eq.' +
        encodeURIComponent(email) +
        '&limit=1';

    const members = await fetchJson(url, {
        method: 'GET',
        headers: config.headers
    });

    if (!Array.isArray(members) || members.length !== 1) {
        throw Object.assign(
            new Error('Member record not found'),
            { status: 404 }
        );
    }

    return members[0].id;
}

function validateReflection(body) {
    if (!isValidDate(body.log_date)) {
        throw Object.assign(
            new Error('Invalid reflection date'),
            { status: 400 }
        );
    }

    if (!isValidDate(body.today)) {
        throw Object.assign(
            new Error('A valid local today date is required'),
            { status: 400 }
        );
    }

    if (isAfterDate(body.log_date, body.today)) {
        throw Object.assign(
            new Error('Future reflection dates are not allowed'),
            { status: 400 }
        );
    }

    const reflection = {
        log_date: body.log_date
    };

    for (const field of FIELDS) {
        const value = body[field];

        if (value === null || value === undefined || value === '') {
            reflection[field] = null;
            continue;
        }

        if (
            !Number.isInteger(value) ||
            value < 1 ||
            value > 5
        ) {
            throw Object.assign(
                new Error(
                    'Reflection ratings must be whole numbers from 1 to 5, or left blank'
                ),
                { status: 400 }
            );
        }

        reflection[field] = value;
    }

    return reflection;
}

async function saveReflection(
    memberId,
    reflection,
    config
) {
    const existingUrl =
        config.url +
        '/rest/v1/daily_logs?select=id,locked' +
        '&member_id=eq.' + encodeURIComponent(memberId) +
        '&log_date=eq.' + encodeURIComponent(reflection.log_date);

    const existing = await fetchJson(existingUrl, {
        method: 'GET',
        headers: config.headers
    });

    if (Array.isArray(existing) && existing.length > 0) {
        if (existing[0].locked === true) {
            throw Object.assign(
                new Error('This reflection is locked and cannot be changed'),
                { status: 409 }
            );
        }
    }

    const saveUrl =
        config.url +
        '/rest/v1/daily_logs?on_conflict=member_id,log_date';

    const saved = await fetchJson(saveUrl, {
        method: 'POST',
        headers: {
            ...config.headers,
            'Content-Type': 'application/json',
            Prefer: 'resolution=merge-duplicates,return=representation'
        },
        body: JSON.stringify({
            ...reflection,
            member_id: memberId
        })
    });

    if (!Array.isArray(saved) || saved.length !== 1) {
        throw Object.assign(
            new Error('Reflection could not be saved'),
            { status: 502 }
        );
    }

    return saved[0];
}


async function getReflectionHistory(
    memberId,
    today,
    config
) {
    if (!isValidDate(today)) {
        throw Object.assign(
            new Error('A valid today date is required'),
            { status: 400 }
        );
    }

    const start = new Date(
        today + 'T00:00:00.000Z'
    );

    start.setUTCDate(start.getUTCDate() - 2);

    const startDate = start.toISOString().slice(0, 10);

    const url =
        config.url +
        '/rest/v1/daily_logs?select=id,log_date,well_being,sleep_quality,active_days,physical_energy,diet_quality,food_confidence,locked,confirmed_at,created_at' +
        '&member_id=eq.' + encodeURIComponent(memberId) +
        '&log_date=gte.' + startDate +
        '&log_date=lte.' + today +
        '&order=log_date.desc';

    return await fetchJson(url, {
        method: 'GET',
        headers: config.headers
    });
}

module.exports = async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');

    if (!['GET', 'POST'].includes(req.method)) {
        res.setHeader('Allow', 'GET, POST');

        return respond(res, 405, {
            error: 'Method not allowed'
        });
    }

    try {
        const email = getSessionEmail(req);
        const config = getSupabaseConfig();
        const memberId = await getMemberId(email, config);

        if (req.method === 'POST') {
            let body;

            try {
                body = parseJson(req.body);
            } catch {
                return respond(res, 400, {
                    error: 'Invalid request data'
                });
            }

            const reflection = validateReflection(body);

            const saved = await saveReflection(
                memberId,
                reflection,
                config
            );

            return respond(res, 200, {
                success: true,
                reflection: saved
            });
        }

        const today = req.query?.today;

        const reflections = await getReflectionHistory(
            memberId,
            today,
            config
        );

        return respond(res, 200, {
            success: true,
            reflections
        });

    } catch (error) {
        const status = error.status || 500;

        if (status === 500) {
            console.error(
                'Daily reflections API error:',
                error
            );
        }

        return respond(res, status, {
            error: status >= 500
                ? 'Unable to process reflection request'
                : error.message
        });
    }
};
