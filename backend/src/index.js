require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const morgan       = require('morgan');
const rateLimit    = require('express-rate-limit');

const scanRoutes   = require('./routes/scan');
const fixRoutes    = require('./routes/fix');
const githubRoutes = require('./routes/github');
const badgeRoutes  = require('./routes/badge');

const app  = express();
const PORT = process.env.PORT || 4000;

const hasGroq      = !!process.env.GROQ_API_KEY;
const hasAnthropic = !!process.env.ANTHROPIC_API_KEY;
const hasAI        = hasGroq || hasAnthropic;
const aiProvider   = hasGroq ? 'groq' : hasAnthropic ? 'claude' : 'none';

app.use(helmet({ crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(morgan('dev'));
app.use(express.json({ limit: '2mb' }));

app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Too many requests. Please wait 15 minutes.' }
}));

app.get('/', (_, res) => res.json({
  name: 'CodeFortress CI API', version: '1.0.0', status: 'online',
  features: { secretDetection: true, sastAnalysis: true, aiAutoFix: hasAI, aiProvider, githubPR: !!process.env.GITHUB_TOKEN }
}));

app.get('/api/health', (_, res) => res.json({
  status: 'healthy', timestamp: new Date().toISOString(),
  claude: hasAI, aiProvider, groq: hasGroq, anthropic: hasAnthropic,
  github: !!process.env.GITHUB_TOKEN
}));

app.use('/api/scan',   scanRoutes);
app.use('/api/fix',    fixRoutes);
app.use('/api/github', githubRoutes);
app.use('/api/badge',  badgeRoutes);

app.use((_, res) => res.status(404).json({ error: 'Route not found' }));
app.use((err, _, res, __) => { console.error(err.stack); res.status(500).json({ error: err.message }); });

app.listen(PORT, () => {
  console.log('\n🛡️  CodeFortress CI Backend');
  console.log('📡  http://localhost:' + PORT);
  console.log('🤖  AI: ' + (hasGroq ? '✅ Groq' : hasAnthropic ? '✅ Claude' : '❌ No key'));
  console.log('🐙  GitHub: ' + (process.env.GITHUB_TOKEN ? '✅ Ready' : '⚠️  Not set') + '\n');
  if (process.env.NODE_ENV === 'production') {
    const http = require('http');
    setInterval(() => {
      try { http.get('http://localhost:' + PORT + '/api/health', r => console.log('[keep-alive]', r.statusCode)).on('error', ()=>{}); } catch(e) {}
    }, 14 * 60 * 1000);
  }
});

module.exports = app;
