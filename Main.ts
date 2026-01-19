import 'dotenv/config'
import express from 'express'
import type {NextFunction, Request, Response} from 'express'
import { rateLimit } from 'express-rate-limit'
import {Pool} from 'pg'
import type {QueryResult} from 'pg'
import crypto from 'crypto'

const app = express()
app.use(express.json())
const port = process.env.PORT ? parseInt(process.env.PORT) : 1000

const anonLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	limit: 1000,
	standardHeaders: 'draft-8',
	legacyHeaders: false,
    statusCode: 429,
    message: {msg:'Too many requests'}
})

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 1000,
    standardHeaders: 'draft-8',
	legacyHeaders: false,
    statusCode: 429,
    keyGenerator: (req) => req.apiKeyHash!,
    message: {msg:'Too many requests'}
})

const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_DATABASE || 'postgres',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'password',
    port: parseInt(process.env.DB_PORT || '5432')
})

pool.on('error', (err) => {
    console.error('Postgres Error:',err);
    process.exit(-1);
});

declare module 'express' {
    interface Request {
        user?: { id: number };
        apiKeyHash?: string;
    }
}

interface userDetails{
    id:number
    email:string
    created_at:string
}


async function authAPI(req:Request,res:Response,next:NextFunction){
    const api = req.header('Authorization')
    if (!api?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing or invalid API key format' })

    try {
        const API = api.split(' ')[1];
        if (!API) return res.status(401).json({ error: 'Missing API key' })
        const hash = hashApiKey(API);
        const cmd = 'SELECT user_id FROM api_keys WHERE hash = $1 AND revoked = false';
        const result:QueryResult<{user_id: number}> = await pool.query(cmd, [hash]);
        if (!result.rows.length) return res.status(401).json({ error: 'Invalid API key' })
        const row = result.rows[0];
        req.user = { id: row.user_id };
        req.apiKeyHash = hash;
        next();
    } catch (err:any){
        console.error('Auth error:', err.message)
        res.status(500).send('Server Error');
    }
}

function generateApiKey(): string {
    return crypto.randomBytes(32).toString("hex");
}

function hashApiKey(apiKey: string): string {
    return crypto.createHash("sha256").update(apiKey).digest("hex");
}



app.get('/data/:id', authAPI, apiLimiter, async (req: Request<{id: string}>, res: Response) => {
    try {
        const userId = parseInt(req.params.id)
        if (isNaN(userId) || userId !== req.user!.id) {
            return res.status(403).json({ error: 'Access denied' })
        }
        res.status(200).json({ msg: 'Access granted', userId })
    } catch (err: any) {
        console.error('Data access error:', err.message)
        res.status(500).send('Server Error')
    }
})

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

app.post('/signUp', anonLimiter, async (req: Request<{}, {}, {email: string}>, res: Response<{msg: userDetails} | {error: string}>) => {
    try {
        const { email } = req.body
        if (!email || !emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' })
        }
        const cmd = 'INSERT INTO users (email) VALUES ($1) RETURNING id, email, created_at;'
        const result: QueryResult<userDetails> = await pool.query(cmd, [email])
        res.status(201).json({ msg: result.rows[0] })
    } catch (err: any) {
        if (err.code === '23505') { // unique violation
            return res.status(409).json({ error: 'Email already exists' })
        }
        console.error('Signup error:', err.message)
        res.status(500).json({ error: 'Server Error' })
    }
})

app.post('/apiKey/:id', async (req: Request<{id: string}>, res: Response<{msg: string} | {error: string}>) => {
    try {
        const userId = parseInt(req.params.id)
        if (isNaN(userId)){
            return res.status(403).json({ error: 'Access denied' })
        }
        const apiKey = generateApiKey()
        const hash = hashApiKey(apiKey)
        await pool.query(
            `INSERT INTO api_keys (user_id, hash) VALUES ($1, $2)`,
            [userId, hash]
        )
        res.status(201).json({ msg: apiKey })
    } catch (err: any) {
        console.error('API key generation error:', err.message)
        res.status(500).json({ error: 'Server Error' })
    }
})

app.listen(port,() =>{ 
    console.log(`Server running on port ${port}`)
})

