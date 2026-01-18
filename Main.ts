import express from 'express'
import type {NextFunction, Request, Response} from 'express'
import { rateLimit } from 'express-rate-limit'
import {Pool} from 'pg'
import type {QueryResult} from 'pg'
import crypto from 'crypto'

const app = express()
app.use(express.json())
const port = 1000

const anonLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, 
	limit: 1000, 
	standardHeaders: 'draft-8',
	legacyHeaders: false, 
	ipv6Subnet: 56,
    statusCode: 429,
    message: {msg:'Too many requests'}
})

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 1000,
    standardHeaders: 'draft-8',
	legacyHeaders: false, 
	ipv6Subnet: 56,
    statusCode: 429,
    keyGenerator: (req) => req.user!.id.toString(),
    message: {msg:'Too many requests'}
})


const pool = new Pool({
    host: 'localhost',
    database: 'postgres',
    user:'postgres',
    password: 'makky1010',
    port: 5432
})

pool.on('error', (err) => {
    console.error('Postgres Error:',err);
    process.exit(-1);
});


declare module 'express' {
    interface Request {
        user?: { id: number };
    }
}

interface userDetails{
    id:number
    email:string
    created_at:string
}


async function authAPI(req:Request,res:Response,next:NextFunction){
    const api = req.header('Authorization')
    if (!api?.startsWith('Bearer')) return res.status(401).json({ error: 'Missing API key' })

    try {
        const API = api.split(' ')[1];
        const cmd = 'SELECT user_id FROM api_keys WHERE hash = ($1) AND revoked = false';
        const result:QueryResult<{user_id: number, hashApi: string}> = await pool.query(cmd, [hashApiKey(API)]);
        if (!result.rows.length) return res.status(401).json({ error: 'Invalid API key' })
        const row = result.rows[0];
        req.user = { id: row.user_id };
        next();
    } catch (err:any){
        console.error('error -->',err.message)
        res.status(500).send('Server Error');
    }
}

function generateApiKey(): string {
    return crypto.randomBytes(32).toString("hex");
}

function hashApiKey(apiKey: string): string {
    return crypto.createHash("sha256").update(apiKey).digest("hex");
}



app.get('/data',authAPI,apiLimiter,async (req:Request,res:Response) =>{
    try{
        res.status(200).json({msg: 'We are done!',userId: req.user!.id})
    }catch(err:any){
        console.error('error -->',err.message)
        res.status(500).send('Server Error')
    }
})

app.post('/signUp',anonLimiter,async (req: Request<{}, {}, {email: string}>,res:Response<{msg: userDetails} | string>) => {
    try{
        const {email} = req.body
        if (!email || !email.includes('@')) return res.status(400).send('Invalid email')
        const cmd = 'INSERT INTO users (email) VALUES ($1) RETURNING *;'
        const result:QueryResult<userDetails> = await pool.query(cmd, [email])
        res.status(201).json({msg: result.rows[0]})
    }catch(err:any){
        console.error('error -->',err.message)
        res.status(500).send('Server Error')
    }
})

app.post('/apiKey',async (req: Request,res:Response<{msg:string} | string>) => {
    try{
        const apiKey = generateApiKey()
        const hash = hashApiKey(apiKey)
        await pool.query(
        `INSERT INTO api_keys (user_id, hash)
        VALUES ($1, $2)`,
        [req.user!.id, hash]
        )
        res.status(201).json({msg: apiKey })
    }catch(err:any){
        console.error('error -->',err.message)
        res.status(500).send('Server Error')
    }
})

app.listen(port,() =>{ 
    console.log(`Server running on port ${port}`)
})
