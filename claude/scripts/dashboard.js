import http from 'http';
import fs from 'fs';
import path from 'path';
import os from 'os';

const port = 3456;
const claudeDir = path.join(os.homedir(), '.claude', 'projects');

const server = http.createServer((req, res) => {
  let totalSessions = 0;
  let estTokens = 0;
  
  try {
    if (fs.existsSync(claudeDir)) {
      const projects = fs.readdirSync(claudeDir);
      for (const proj of projects) {
         const projPath = path.join(claudeDir, proj);
         if (fs.statSync(projPath).isDirectory()) {
            const files = fs.readdirSync(projPath).filter(f => f.endsWith('.jsonl'));
            totalSessions += files.length;

            for (const file of files) {
               const content = fs.readFileSync(path.join(projPath, file), 'utf8');
               const lines = content.split('\n').filter(Boolean);
               for (const line of lines) {
                 try {
                   const parsed = JSON.parse(line);
                   if (parsed.message && parsed.message.usage) {
                     estTokens += (parsed.message.usage.input_tokens || 0) + (parsed.message.usage.output_tokens || 0);
                   }
                 } catch(e) {}
               }
            }
         }
      }
    }
  } catch(e) {
    console.error('Error reading sessions:', e);
  }

  const html = \
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <title>Claude Credit Dashboard</title>
    <style>
      body { font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
      .card { background: #161b22; padding: 2rem; border-radius: 8px; border: 1px solid #30363d; max-width: 600px; margin: 0 auto; }
      h1 { color: #58a6ff; }
      .metric { font-size: 2rem; font-weight: bold; margin-bottom: 0.5rem; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Claude Credit Analytics</h1>
      <p>Analyzing local JSONL session data...</p>
      <div class="metric">\</div>
      <p>Total Sessions</p>
      <div class="metric">\</div>
      <p>Total Tokens Processed</p>
    </div>
  </body>
  </html>
  \;

  res.writeHead(200, {'Content-Type': 'text/html'});
  res.end(html);
});

server.listen(port, () => console.log('Dashboard running on http://localhost:' + port));
