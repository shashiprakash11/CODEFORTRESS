require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const morgan       = require('morgan');
const rateLimit    = require('express-rate-limit');

const scanRoutes   = require('./routes/scan');
const fixRoutes    = require('./routes/fix');
const githubRoutes = require('./routes/github');

const app  = express();
const PORT = process.env.PORT || 4000;

// ── Middleware
app.use(helmet({ crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(morgan('dev'));
app.use(express.json({ limit: '2mb' }));

// ── Rate limiting (50 requests per 15 min per IP)
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Too many requests. Please wait 15 minutes.' }
}));

// ── Routes
app.get('/', (_, res) => res.json({
  name:    'CodeFortress CI API',
  version: '1.0.0',
  status:  'online',
  features: {
    secretDetection: true,
    sastAnalysis:    true,
    aiAutoFix:       !!process.env.ANTHROPIC_API_KEY,
    githubPR:        !!process.env.GITHUB_TOKEN
  }
}));

app.get('/api/health', (_, res) => res.json({
  status:    'healthy',
  timestamp: new Date().toISOString(),
  claude:    !!process.env.ANTHROPIC_API_KEY,
  github:    !!process.env.GITHUB_TOKEN
}));

app.use('/api/scan',   scanRoutes);
app.use('/api/fix',    fixRoutes);
app.use('/api/github', githubRoutes);

// ── 404
app.use((_, res) => res.status(404).json({ error: 'Route not found' }));

// ── Error handler
app.use((err, _, res, __) => {
  console.error(err.stack);
  res.status(500).json({ error: err.message });
});

app.listen(PORT, () => {
  console.log('\n🛡️  CodeFortress CI Backend');
  console.log('📡  http://localhost:' + PORT);
  console.log('🤖  Claude API: ' + (process.env.ANTHROPIC_API_KEY ? '✅ Ready' : '❌ Not set'));
  console.log('🐙  GitHub:     ' + (process.env.GITHUB_TOKEN     ? '✅ Ready' : '⚠️  Not set (public repos only)') + '\n');

  // Keep-alive ping every 14 minutes to prevent Railway free tier sleep
  if(process.env.NODE_ENV === 'production') {
    const http = require('http');
    setInterval(() => {
      try {
        http.get('http://localhost:' + PORT + '/api/health', (res) => {
          console.log('Keep-alive ping: ' + res.statusCode);
        }).on('error', () => {});
      } catch(e) {}
    }, 14 * 60 * 1000);
  }
});

module.exports = app;
