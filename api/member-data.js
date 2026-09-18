
module.exports = async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({
            error: 'Method not allowed'
        });
    }

    try {
        const cookieHeader = req.headers.cookie || '';

        const cookies = cookieHeader
            .split(';')
            .map(function (item) {
                return item.trim();
            });

        const sessionCookie = cookies.find(function (item) {
            return item.startsWith('mirror_me_session=');
        });

        if (!sessionCookie) {
            return res.status(401).json({
                error: 'Not authenticated'
            });
        }

        const session = sessionCookie.substring(
            'mirror_me_session='.length
        );

        const parts = session.split('.');

        if (parts.length !== 2) {
            return res.status(401).json({
                error: 'Invalid session'
            });
        }

        const payloadString = parts[0];
        const receivedSignature = parts[1];

        const crypto = require('node:crypto');

        const secret = process.env.M_SESSION_SECRET;

        if (!secret) {
            console.error('M_SESSION_SECRET is missing');

            return res.status(500).json({
                error: 'Server configuration error'
            });
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
            return res.status(401).json({
                error: 'Invalid session'
            });
        }

        let payload;

        try {
            payload = JSON.parse(
                Buffer.from(
                    payloadString,
                    'base64url'
                ).toString('utf8')
            );
        } catch (error) {
            return res.status(401).json({
                error: 'Invalid session payload'
            });
        }

        if (
            !payload.email ||
            !payload.exp ||
            Date.now() > Number(payload.exp)
        ) {
            return res.status(401).json({
                error: 'Session expired'
            });
        }

        const email = String(payload.email)
            .trim()
            .toLowerCase();

        const supabaseUrl =
            process.env.SUPABASE_URL;

        const serviceRoleKey =
            process.env.SUPABASESERVICEROLEKEY;

        if (!supabaseUrl || !serviceRoleKey) {
            console.error(
                'Supabase environment variables are missing'
            );

            return res.status(500).json({
                error: 'Server configuration error'
            });
        }

        const url =
            supabaseUrl +
            '/rest/v1/member_calculations' +
            '?select=*' +
            '&email=eq.' +
            encodeURIComponent(email) +
            '&limit=1';

        const response = await fetch(url, {
            method: 'GET',
            headers: {
                apikey: serviceRoleKey,
                Authorization: 'Bearer ' + serviceRoleKey,
                Accept: 'application/json'
            }
        });

        const responseText = await response.text();

        if (!response.ok) {
            console.error(
                'Supabase member_calculations error:',
                response.status,
                responseText
            );

            return res.status(500).json({
                error: 'Unable to load member data'
            });
        }

        let members;

        try {
            members = JSON.parse(responseText);
        } catch (error) {
            console.error(
                'Invalid Supabase response:',
                responseText
            );

            return res.status(500).json({
                error: 'Invalid member data response'
            });
        }

        if (!Array.isArray(members) || members.length === 0) {
            console.error(
                'No member_calculations row found for:',
                email
            );

            return res.status(404).json({
                error: 'No member data found'
            });
        }

        const member = members[0];

        return res.status(200).json({
            id: member.id,
            submission_id: member.submission_id,
            uid: member.uid,
            user_id: member.user_id,
            name: member.name,
            email: member.email,
            dob: member.dob,
            sex: member.sex,
            bmi: member.bmi,
            whr: member.whr,
            gut_health_score: member.gut_health_score,
            gut_health_insights: member.gut_health_insights,
            gut_clinical_insights: member.gut_clinical_insights,
            gut_action: member.gut_action,
            allergy_severity: member.allergy_severity,
            stress_score: member.stress_score,
            stress_interpretation: member.stress_interpretation,
            stress_clinical: member.stress_clinical,
            stress_action: member.stress_action,
            musculoskeletal_score: member.musculoskeletal_score,
            musculoskeletal_interpretation: member.musculoskeletal_interpretation,
            muscle_clinical: member.muscle_clinical,
            muscle_action: member.muscle_action,
            metabolic_score: member.metabolic_score,
            metabolic_interpretation: member.metabolic_interpretation,
            metabolic_clinical: member.metabolic_clinical,
            metabolic_action: member.metabolic_action,
            metabolic_age: member.metabolic_age,
            biological_age: member.biological_age,
            age_difference: member.age_difference,
            age_interpretation: member.age_interpretation,
            nutritional_recommendations: member.nutritional_recommendations,
            deficiency_micros: member.deficiency_micros,
            synergy: member.synergy,
            food_sources: member.food_sources,
            submitted_at: member.submitted_at,
            age: member.age,
            status: member.status,
            site_url: member.site_url,
            access_key: member.access_key,
            created_at: member.created_at,
            updated_at: member.updated_at
        });

    } catch (error) {
        console.error(
            'Member data API error:',
            error
        );

        return res.status(500).json({
            error: 'Server error'
        });
    }
};
```
