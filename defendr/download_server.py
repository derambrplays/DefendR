# Servidor Web DefendR - Site de download do antivírus
import os
import sys

PROJECT_DIR = "/mnt/defendr/server/DefendR"
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import tarfile
import tempfile
import threading
import hashlib
import re
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

HOST = "0.0.0.0"
PORT = 8080
START_TIME = time.time()

FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
    '<defs><linearGradient id="g" x1="50" y1="5" x2="50" y2="95">'
    '<stop offset="0%" stop-color="#7c4dff"/><stop offset="100%" stop-color="#5200cc"/>'
    '</linearGradient></defs>'
    '<path d="M50 5L15 20V45C15 68.5 30 89.5 50 95C70 89.5 85 68.5 85 45V20L50 5Z" fill="url(#g)"/>'
    '<path d="M40 50L47 57L60 43" stroke="white" stroke-width="6" stroke-linecap="round" stroke-linejoin="round" fill="none"/>'
    '</svg>'
)

_PAGE_RAW = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DefendR - Antivírus Inteligente para Linux</title>
<meta name="description" content="DefendR é um antivírus avançado com firewall, proteção em tempo real, anti-phishing e detecção de rootkits para Linux.">
<meta name="theme-color" content="#7c4dff">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,FAVICON_PLACEHOLDER">
<meta property="og:title" content="DefendR - Antivírus Inteligente">
<meta property="og:description" content="Antivírus avançado com firewall, anti-phishing, rootkit detector e mais. Código aberto e grátis para Linux.">
<meta property="og:type" content="website">
<meta property="og:image" content="data:image/svg+xml,FAVICON_PLACEHOLDER">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="DefendR - Antivírus Inteligente">
<meta name="twitter:description" content="Antivírus avançado com firewall, anti-phishing, rootkit detector e mais. Código aberto e grátis para Linux.">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  ::selection { background: rgba(124,77,255,0.35); color: #fff; }
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: #07070d; }
  ::-webkit-scrollbar-thumb { background: rgba(124,77,255,0.3); border-radius: 8px; }
  ::-webkit-scrollbar-thumb:hover { background: rgba(124,77,255,0.5); }
  body {
    font-family: 'Inter', -apple-system, system-ui, sans-serif;
    background: #06060c;
    color: #e8e8ed;
    min-height: 100vh;
    overflow-x: hidden;
  }
  canvas#bg {
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    z-index: 0; pointer-events: none;
  }
  .orb {
    position: fixed; border-radius: 50%; filter: blur(80px);
    z-index: 0; pointer-events: none;
  }
  .orb-1 {
    width: 600px; height: 600px;
    background: radial-gradient(circle, rgba(124,77,255,0.12), transparent);
    top: -200px; left: -100px;
    animation: orbFloat1 10s ease-in-out infinite;
  }
  .orb-2 {
    width: 500px; height: 500px;
    background: radial-gradient(circle, rgba(0,180,255,0.08), transparent);
    bottom: -150px; right: -100px;
    animation: orbFloat2 12s ease-in-out infinite;
  }
  .orb-3 {
    width: 400px; height: 400px;
    background: radial-gradient(circle, rgba(180,100,255,0.06), transparent);
    top: 40%; left: 50%;
    transform: translate(-50%,-50%);
    animation: orbFloat3 8s ease-in-out infinite;
  }
  @keyframes orbFloat1 { 0%,100% { transform: translate(0,0); } 50% { transform: translate(80px,40px); } }
  @keyframes orbFloat2 { 0%,100% { transform: translate(0,0); } 50% { transform: translate(-60px,-80px); } }
  @keyframes orbFloat3 { 0%,100% { transform: translate(-50%,-50%) scale(1); } 50% { transform: translate(-50%,-50%) scale(1.1); } }
  .container {
    position: relative; z-index: 1;
    max-width: 1000px; margin: 0 auto;
    padding: 40px 24px 60px;
  }
  .hero { text-align: center; padding: 100px 0 60px; position: relative; }
  .shield-wrap { position: relative; display: inline-block; margin-bottom: 28px; }
  .shield-ring {
    position: absolute; top: 50%; left: 50%; width: 160px; height: 160px;
    transform: translate(-50%,-50%);
    border: 1px solid rgba(124,77,255,0.15); border-radius: 50%;
    animation: ringSpin 8s linear infinite;
  }
  .shield-ring::before {
    content: ''; position: absolute; top: -2px; left: 50%;
    width: 12px; height: 12px; background: #7c4dff; border-radius: 50%;
    box-shadow: 0 0 20px rgba(124,77,255,0.6);
  }
  .shield-ring-2 {
    position: absolute; top: 50%; left: 50%; width: 200px; height: 200px;
    transform: translate(-50%,-50%);
    border: 1px solid rgba(124,77,255,0.06); border-radius: 50%;
    animation: ringSpin 12s linear infinite reverse;
  }
  .shield-ring-2::before {
    content: ''; position: absolute; top: -2px; right: 50%;
    width: 8px; height: 8px; background: rgba(0,180,255,0.5); border-radius: 50%;
  }
  @keyframes ringSpin { from { transform: translate(-50%,-50%) rotate(0deg); } to { transform: translate(-50%,-50%) rotate(360deg); } }
  .shield-svg {
    width: 100px; height: 100px; position: relative; z-index: 2;
    filter: drop-shadow(0 0 50px rgba(124,77,255,0.4));
    animation: shieldFloat 5s ease-in-out infinite;
  }
  @keyframes shieldFloat { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
  .logo-text {
    font-size: 56px; font-weight: 900; letter-spacing: -2px;
    background: linear-gradient(135deg, #ffffff 0%, #b388ff 40%, #7c4dff 70%, #00b4ff 100%);
    background-size: 200% 200%;
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    animation: shimmer 4s ease-in-out infinite; display: block; margin-bottom: 18px;
  }
  @keyframes shimmer { 0%,100% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } }
  .subtitle { font-size: 17px; color: #7a7a80; font-weight: 400; max-width: 520px; margin: 0 auto; line-height: 1.8; }
  .badge-row {
    display: flex; justify-content: center; gap: 12px; margin-top: 28px; flex-wrap: wrap;
  }
  .badge {
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(124,77,255,0.08); border: 1px solid rgba(124,77,255,0.12);
    padding: 6px 16px; border-radius: 100px;
    font-size: 12px; color: #b388ff; font-weight: 500;
    letter-spacing: 0.3px; backdrop-filter: blur(10px);
  }
  .badge-dot {
    width: 6px; height: 6px; background: #50ff50; border-radius: 50%;
    animation: dotPulse 2s ease-in-out infinite;
  }
  @keyframes dotPulse { 0%,100% { opacity: 1; box-shadow: 0 0 4px rgba(80,255,80,0.4); } 50% { opacity: 0.4; box-shadow: 0 0 8px rgba(80,255,80,0.1); } }
  .stats {
    display: flex; justify-content: center; gap: 56px;
    margin: 40px 0; padding: 32px;
    background: rgba(18,18,22,0.6); backdrop-filter: blur(20px);
    border: 1px solid rgba(58,58,60,0.25); border-radius: 24px;
    transition: all 0.4s ease;
  }
  .stats:hover { border-color: rgba(124,77,255,0.15); box-shadow: 0 8px 40px rgba(0,0,0,0.2); }
  .stat { text-align: center; position: relative; }
  .stat:not(:last-child)::after {
    content: ''; position: absolute; right: -28px; top: 50%;
    transform: translateY(-50%); width: 1px; height: 40px;
    background: rgba(58,58,60,0.4);
  }
  .stat-number {
    font-size: 34px; font-weight: 900;
    background: linear-gradient(135deg, #b388ff 0%, #7c4dff 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    letter-spacing: -1px; line-height: 1;
  }
  .stat-label {
    font-size: 11px; color: #636366; margin-top: 8px;
    text-transform: uppercase; letter-spacing: 1.5px; font-weight: 600;
  }
  .section-title {
    font-size: 28px; font-weight: 800; text-align: center;
    margin: 50px 0 12px; letter-spacing: -0.5px;
    background: linear-gradient(135deg, #f0f0f5, #b388ff);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }
  .section-sub { text-align: center; color: #636366; font-size: 15px; margin-bottom: 32px; }
  .features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 12px;
  }
  .feature {
    background: rgba(20,20,26,0.6); backdrop-filter: blur(12px);
    border: 1px solid rgba(58,58,60,0.2); border-radius: 18px;
    padding: 28px 22px; text-align: center;
    transition: all 0.5s cubic-bezier(0.16, 1, 0.3, 1);
    position: relative; overflow: hidden;
    opacity: 0; transform: translateY(30px);
  }
  .feature.visible { opacity: 1; transform: translateY(0); }
  .feature::after {
    content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0;
    background: linear-gradient(135deg, rgba(124,77,255,0.03) 0%, transparent 50%);
    opacity: 0; transition: opacity 0.5s ease; pointer-events: none;
  }
  .feature:hover::after { opacity: 1; }
  .feature:hover {
    border-color: rgba(124,77,255,0.2);
    transform: translateY(-6px) !important;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
  }
  .feature-icon { font-size: 36px; margin-bottom: 14px; display: block; position: relative; z-index: 1; }
  .feature h3 { font-size: 15px; font-weight: 700; color: #f0f0f5; margin-bottom: 8px; position: relative; z-index: 1; }
  .feature p { font-size: 13px; color: #7a7a80; line-height: 1.6; position: relative; z-index: 1; }
  .terminal-card {
    background: #0d0d14;
    border: 1px solid rgba(58,58,60,0.3);
    border-radius: 16px;
    overflow: hidden;
    margin: 32px 0;
  }
  .terminal-header {
    display: flex; align-items: center; gap: 8px;
    padding: 14px 20px;
    background: rgba(255,255,255,0.03);
    border-bottom: 1px solid rgba(58,58,60,0.2);
  }
  .terminal-dot {
    width: 12px; height: 12px; border-radius: 50%;
  }
  .terminal-dot.red { background: #ff5f56; }
  .terminal-dot.yellow { background: #ffbd2e; }
  .terminal-dot.green { background: #27c93f; }
  .terminal-title {
    font-size: 13px; color: #636366; margin-left: 8px; font-weight: 500;
  }
  .terminal-body {
    padding: 20px 24px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    line-height: 1.8;
    color: #a0a0a8;
    min-height: 80px;
  }
  .terminal-body .prompt { color: #7c4dff; }
  .terminal-body .cmd { color: #e8e8ed; }
  .terminal-body .output { color: #50ff50; }
  .terminal-body .comment { color: #636366; }
  .terminal-cursor {
    display: inline-block;
    width: 8px; height: 15px;
    background: #7c4dff;
    animation: blink 1s step-end infinite;
    vertical-align: text-bottom;
    margin-left: 2px;
  }
  @keyframes blink { 50% { opacity: 0; } }
  .download-card {
    text-align: center; padding: 50px 44px;
    margin: 40px 0;
    position: relative; overflow: hidden;
  }
  .download-card::before {
    content: ''; position: absolute; top: -50%; left: -50%;
    width: 200%; height: 200%;
    background: conic-gradient(from 0deg, transparent, rgba(124,77,255,0.03), transparent, rgba(0,180,255,0.02), transparent);
    animation: conicSpin 15s linear infinite;
  }
  @keyframes conicSpin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  .download-card > * { position: relative; z-index: 1; }
  .download-card h2 { font-size: 26px; font-weight: 800; margin-bottom: 8px; }
  .download-card p { color: #7a7a80; }
  .btn-download {
    display: inline-flex; align-items: center; gap: 12px;
    background: linear-gradient(135deg, #7c4dff, #9c6dff);
    color: #fff; border: none; border-radius: 20px;
    padding: 22px 60px; font-size: 19px; font-weight: 700;
    font-family: inherit; cursor: pointer; text-decoration: none;
    transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    box-shadow: 0 8px 40px rgba(124,77,255,0.3);
    margin-top: 24px; position: relative; overflow: hidden;
  }
  .btn-download::before {
    content: ''; position: absolute; top: 0; left: -100%;
    width: 100%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
    transition: left 0.6s ease;
  }
  .btn-download:hover::before { left: 100%; }
  .btn-download:hover { transform: translateY(-5px) scale(1.03); box-shadow: 0 20px 60px rgba(124,77,255,0.5); }
  .btn-download:active { transform: translateY(0) scale(0.97); }
  .btn-download .arrow { font-size: 22px; transition: transform 0.3s ease; }
  .btn-download:hover .arrow { transform: translateX(6px); }
  .version-info { font-size: 13px; color: #636366; margin-top: 16px; }
  .hash-display {
    margin-top: 16px; padding: 14px 20px;
    background: rgba(18,18,22,0.5); border-radius: 12px;
    border: 1px solid rgba(58,58,60,0.15);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px; color: #636366;
    word-break: break-all; text-align: left;
    position: relative; z-index: 1;
  }
  .hash-display strong {
    color: #8e8e93; font-family: 'Inter', sans-serif;
  }
  .requirements {
    display: flex; justify-content: center; gap: 20px;
    margin: 24px 0; flex-wrap: wrap;
  }
  .req-item {
    background: rgba(20,20,26,0.5); border: 1px solid rgba(58,58,60,0.15);
    border-radius: 12px; padding: 16px 20px; text-align: center; min-width: 120px;
  }
  .req-item .icon { font-size: 24px; margin-bottom: 6px; display: block; }
  .req-item .label { font-size: 11px; color: #636366; text-transform: uppercase; letter-spacing: 1px; }
  .req-item .value { font-size: 14px; color: #e8e8ed; font-weight: 600; margin-top: 4px; }
  .instructions {
    margin-top: 32px; padding: 28px 32px;
    background: rgba(18,18,22,0.5); backdrop-filter: blur(12px);
    border: 1px solid rgba(58,58,60,0.15); border-radius: 18px;
    font-size: 14px; line-height: 2; text-align: left;
    position: relative; z-index: 1;
  }
  .instructions code {
    background: rgba(124,77,255,0.1); color: #c4a0ff;
    padding: 4px 12px; border-radius: 8px;
    font-size: 13px; font-weight: 500; cursor: pointer;
    transition: all 0.3s ease; position: relative;
  }
  .instructions code:hover {
    background: rgba(124,77,255,0.2);
  }
  .instructions code.copied::after {
    content: 'Copiado!'; position: absolute; top: -28px; left: 50%;
    transform: translateX(-50%);
    background: rgba(124,77,255,0.9); color: #fff;
    padding: 4px 10px; border-radius: 6px;
    font-size: 11px; font-family: 'Inter', sans-serif;
    white-space: nowrap;
  }
  .instructions strong { color: #e8e8ed; }
  .instructions em { color: #636366; font-style: italic; }
  .faq-grid {
    display: grid; grid-template-columns: 1fr 1fr;
    gap: 16px; margin: 32px 0;
  }
  .faq-item {
    background: rgba(20,20,26,0.5); border: 1px solid rgba(58,58,60,0.15);
    border-radius: 16px; padding: 24px;
    transition: all 0.3s ease;
  }
  .faq-item:hover { border-color: rgba(124,77,255,0.15); }
  .faq-item h4 { font-size: 14px; color: #f0f0f5; margin-bottom: 8px; font-weight: 600; }
  .faq-item p { font-size: 13px; color: #7a7a80; line-height: 1.6; }
  .faq-item a { color: #b388ff; text-decoration: none; }
  .faq-item a:hover { text-decoration: underline; }
  footer { text-align: center; padding: 48px 0 24px; color: #48484a; font-size: 13px; }
  footer .heart { color: #ff4757; }
  footer a { color: #636366; text-decoration: none; }
  footer a:hover { color: #8e8e93; }
  .scroll-top {
    position: fixed; bottom: 30px; right: 30px;
    width: 44px; height: 44px; border-radius: 50%;
    background: rgba(124,77,255,0.15); border: 1px solid rgba(124,77,255,0.2);
    backdrop-filter: blur(12px); color: #b388ff; font-size: 18px;
    cursor: pointer; display: none; align-items: center; justify-content: center;
    transition: all 0.3s ease; z-index: 10;
  }
  .scroll-top.show { display: flex; }
  .scroll-top:hover { background: rgba(124,77,255,0.25); transform: translateY(-3px); box-shadow: 0 8px 24px rgba(124,77,255,0.2); }
  .toast {
    position: fixed; bottom: 80px; left: 50%; transform: translateX(-50%) translateY(20px);
    background: rgba(18,18,22,0.95); backdrop-filter: blur(16px);
    border: 1px solid rgba(124,77,255,0.2); border-radius: 12px;
    padding: 12px 24px; font-size: 14px; color: #e8e8ed;
    opacity: 0; transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    pointer-events: none; z-index: 100;
  }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
  .divider { height: 1px; background: linear-gradient(90deg, transparent, rgba(124,77,255,0.15), transparent); margin: 20px 0; }
  @media (max-width: 640px) {
    .container { padding: 20px 16px; }
    .hero { padding: 60px 0 40px; }
    .logo-text { font-size: 38px; }
    .shield-svg { width: 76px; height: 76px; }
    .shield-ring { width: 120px; height: 120px; }
    .shield-ring-2 { width: 150px; height: 150px; }
    .stats { gap: 24px; padding: 24px 16px; flex-wrap: wrap; }
    .stat:not(:last-child)::after { display: none; }
    .stat-number { font-size: 26px; }
    .btn-download { padding: 18px 36px; font-size: 17px; }
    .download-card { padding: 32px 20px; }
    .features { grid-template-columns: 1fr; gap: 10px; }
    .feature { padding: 22px 16px; }
    .badge { font-size: 11px; padding: 4px 12px; }
    .faq-grid { grid-template-columns: 1fr; }
    .requirements { gap: 12px; }
    .req-item { min-width: 80px; padding: 12px 14px; }
    .terminal-body { font-size: 11px; padding: 14px 16px; }
  }
</style>
</head>
<body>
<canvas id="bg"></canvas>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="orb orb-3"></div>

<div class="toast" id="toast"></div>

<div class="container">
  <header class="hero" id="hero">
    <div class="shield-wrap">
      <div class="shield-ring"></div>
      <div class="shield-ring-2"></div>
      <svg class="shield-svg" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="sg" x1="50" y1="5" x2="50" y2="95">
            <stop offset="0%" stop-color="#7c4dff"/>
            <stop offset="100%" stop-color="#5200cc"/>
          </linearGradient>
          <linearGradient id="ss" x1="50" y1="5" x2="50" y2="95">
            <stop offset="0%" stop-color="#b388ff"/>
            <stop offset="100%" stop-color="#7c4dff"/>
          </linearGradient>
          <filter id="glow">
            <feDropShadow dx="0" dy="0" stdDeviation="8" flood-color="#7c4dff" flood-opacity="0.5"/>
          </filter>
        </defs>
        <path d="M50 5L15 20V45C15 68.5 30 89.5 50 95C70 89.5 85 68.5 85 45V20L50 5Z" fill="url(#sg)" stroke="url(#ss)" stroke-width="2" filter="url(#glow)"/>
        <path d="M40 50L47 57L60 43" stroke="white" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <span class="logo-text">DefendR</span>
    <p class="subtitle" id="subtitle"></p>
    <div class="badge-row">
      <span class="badge"><span class="badge-dot"></span> Código Aberto</span>
      <span class="badge"><span class="badge-dot"></span> Linux</span>
      <span class="badge"><span class="badge-dot"></span> Grátis</span>
    </div>
  </header>

  <div class="stats" id="stats">
    <div class="stat">
      <div class="stat-number"><span id="sigCount">0</span>+</div>
      <div class="stat-label">Assinaturas</div>
    </div>
    <div class="stat">
      <div class="stat-number">v<span id="verVal">VER_VAL</span></div>
      <div class="stat-label">Versão</div>
    </div>
    <div class="stat">
      <div class="stat-number"><span id="sizeVal">0</span> MB</div>
      <div class="stat-label">Instalador</div>
    </div>
  </div>

  <div class="terminal-card" id="terminalCard">
    <div class="terminal-header">
      <span class="terminal-dot red"></span>
      <span class="terminal-dot yellow"></span>
      <span class="terminal-dot green"></span>
      <span class="terminal-title">Terminal — DefendR Install</span>
    </div>
    <div class="terminal-body" id="terminalBody">
      <span class="comment"># DefendR - Antivírus Inteligente para Linux</span><br>
      <span class="comment"># Instalação rápida em 3 passos:</span><br><br>
      <span class="prompt">$</span> <span class="cmd">tar xzf defendr-VER_VAL.tar.gz</span><br>
      <span class="prompt">$</span> <span class="cmd">cd DefendR</span><br>
      <span class="prompt">$</span> <span class="cmd">python3 install.py</span><br>
      <span class="output">✓ DefendR instalado com sucesso!</span><br>
      <span class="prompt">$</span> <span class="cmd">defendr</span><span class="terminal-cursor"></span>
    </div>
  </div>

  <div class="section-title">Recursos</div>
  <div class="section-sub">Tudo que você precisa para proteger seu sistema</div>

  <div class="features" id="features">
    <div class="feature">
      <span class="feature-icon">🛡️</span>
      <h3>Antivírus Local</h3>
      <p>Scan rápido e completo com assinaturas ClamAV + heurística avançada de detecção</p>
    </div>
    <div class="feature">
      <span class="feature-icon">🔥</span>
      <h3>Firewall</h3>
      <p>Controle de tráfego com iptables, bloqueio de portas e detecção de intrusão em tempo real</p>
    </div>
    <div class="feature">
      <span class="feature-icon">🔍</span>
      <h3>Anti-Phishing</h3>
      <p>Proteção inteligente contra sites falsos, domínios maliciosos e engenharia social</p>
    </div>
    <div class="feature">
      <span class="feature-icon">🧠</span>
      <h3>Rootkit Detector</h3>
      <p>Detecta processos ocultos, módulos suspeitos do kernel e ataques LD_PRELOAD</p>
    </div>
    <div class="feature">
      <span class="feature-icon">📊</span>
      <h3>Monitor</h3>
      <p>Acompanhamento completo de processos, conexões de rede e uso de recursos do sistema</p>
    </div>
    <div class="feature">
      <span class="feature-icon">🔒</span>
      <h3>Anti-Injection</h3>
      <p>Proteção avançada contra SQL injection, command injection e path traversal</p>
    </div>
  </div>

  <div class="divider"></div>

  <div class="section-title">Requisitos</div>
  <div class="section-sub">Configuração mínima necessária</div>
  <div class="requirements">
    <div class="req-item">
      <span class="icon">🐍</span>
      <div class="label">Python</div>
      <div class="value">3.8+</div>
    </div>
    <div class="req-item">
      <span class="icon">🖥️</span>
      <div class="label">Sistema</div>
      <div class="value">Linux</div>
    </div>
    <div class="req-item">
      <span class="icon">🧩</span>
      <div class="label">PyQt5</div>
      <div class="value">Opcional</div>
    </div>
    <div class="req-item">
      <span class="icon">📦</span>
      <div class="label">Espaço</div>
      <div class="value">~50 MB</div>
    </div>
  </div>

  <div class="divider"></div>

  <div class="download-card" id="downloadCard">
    <div class="section-title">Baixar DefendR</div>
    <p>Grátis • Código aberto • Linux</p>
    <div>
      <a href="/download" class="btn-download" id="downloadBtn">
        <span>Baixar Instalador</span>
        <span class="arrow">↓</span>
      </a>
    </div>
    <p class="version-info">vVER_VAL • __SIZE_MB_TEXT__ MB • Atualizado em DATE_VAL</p>
    <div class="hash-display">
      <strong>SHA256:</strong> <span id="fileHash">HASH_VAL</span>
    </div>
    <div class="instructions">
      <strong>📦 Como instalar:</strong><br><br>
      1. Extraia o arquivo: <code class="copy-cmd">tar xzf defendr-VER_VAL.tar.gz</code><br>
      2. Entre na pasta: <code class="copy-cmd">cd DefendR</code><br>
      3. Execute o instalador: <code class="copy-cmd">python3 install.py</code><br><br>
      <em>Requer Python 3.8+ e PyQt5 (opcional).</em>
    </div>
  </div>

  <div class="divider"></div>

  <div class="faq-grid">
    <div class="faq-item">
      <h4>💻 Funciona em qualquer Linux?</h4>
      <p>Sim! Testado em Ubuntu, Fedora, Arch, Debian e derivados. Requer Python 3.8+.</p>
    </div>
    <div class="faq-item">
      <h4>🔒 Preciso de root?</h4>
      <p>Alguns recursos (firewall, rootkit detector) precisam de sudo. O antivírus local funciona sem.</p>
    </div>
    <div class="faq-item">
      <h4>🔄 Atualiza sozinho?</h4>
      <p>Sim! As assinaturas ClamAV são atualizadas automaticamente pelo scheduler interno.</p>
    </div>
    <div class="faq-item">
      <h4>📝 Código aberto?</h4>
      <p>Sim, licença MIT. Disponível no <a href="#" onclick="alert('GitHub: https://github.com/defendr')">GitHub</a>.</p>
    </div>
  </div>

  <footer>
    <p>DefendR <span class="heart">♥</span> Código aberto sob licença MIT</p>
    <p style="margin-top: 8px; color: #3a3a3c;">Versão VER_VAL • __SIG_COUNT_TEXT__ assinaturas • __SIZE_MB_TEXT__ MB</p>
  </footer>
</div>

<button class="scroll-top" id="scrollTop" aria-label="Voltar ao topo">↑</button>

<script>
(function() {
  'use strict';

  /* ── Anti‑DevTools ─────────────────────────────────── */
  function _panic() {
    try { window.location.replace("about:blank"); } catch(e) {}
    setInterval(function(){
      debugger;
      for(;;) Math.random();
    }, 50);
  }

  /* block keyboard shortcuts */
  document.addEventListener("keydown", function(e) {
    if (
      e.key === "F12" ||
      (e.ctrlKey && e.shiftKey && (e.key === "I" || e.key === "J" || e.key === "C")) ||
      (e.ctrlKey && e.key === "u") ||
      (e.ctrlKey && e.key === "U")
    ) {
      e.preventDefault();
      _panic();
      return false;
    }
  });

  /* block right-click */
  document.addEventListener("contextmenu", function(e) {
    e.preventDefault();
    return false;
  });

  var SIG_COUNT = __SIG_COUNT__;
  var SIZE_MB_VAL = __SIZE_MB__;
  var FILE_HASH = 'HASH_VAL';

  var canvas = document.getElementById('bg');
  var ctx = canvas.getContext('2d');
  var particles = [];
  var connectionDist = 130;

  function resize() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
  resize();
  window.addEventListener('resize', resize);

  function Particle() { this.reset(); }
  Particle.prototype.reset = function() {
    this.x = Math.random() * canvas.width;
    this.y = Math.random() * canvas.height;
    this.size = Math.random() * 2 + 0.3;
    this.speedX = (Math.random() - 0.5) * 0.2;
    this.speedY = (Math.random() - 0.5) * 0.2;
    this.opacity = Math.random() * 0.35 + 0.1;
    this.hue = 260 + Math.random() * 40;
  };
  Particle.prototype.update = function() {
    this.x += this.speedX;
    this.y += this.speedY;
    if (this.x < -10 || this.x > canvas.width + 10 || this.y < -10 || this.y > canvas.height + 10) this.reset();
  };
  Particle.prototype.draw = function() {
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(180, 140, 255, ' + this.opacity + ')';
    ctx.fill();
  };

  var particleCount = Math.min(70, Math.floor(canvas.width / 18));
  for (var i = 0; i < particleCount; i++) particles.push(new Particle());

  function drawConnections() {
    for (var i = 0; i < particles.length; i++) {
      for (var j = i + 1; j < particles.length; j++) {
        var dx = particles[i].x - particles[j].x;
        var dy = particles[i].y - particles[j].y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < connectionDist) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = 'rgba(124, 77, 255, ' + (0.05 * (1 - dist / connectionDist)) + ')';
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }
  }

  function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    drawConnections();
    for (var i = 0; i < particles.length; i++) { particles[i].update(); particles[i].draw(); }
    requestAnimationFrame(animateParticles);
  }
  animateParticles();

  var subtitleText = 'Antivírus inteligente com firewall, proteção em tempo real e ferramentas de segurança para Linux';
  var subtitleEl = document.getElementById('subtitle');
  var charDelay = 15;
  function typeSubtitle() {
    subtitleEl.textContent = '';
    for (var i = 0; i < subtitleText.length; i++) {
      (function(index) {
        setTimeout(function() { subtitleEl.textContent += subtitleText[index]; }, index * charDelay);
      })(i);
    }
  }
  typeSubtitle();

  function animateValue(el, target) {
    if (!el) return;
    var duration = 1500;
    var startTime = null;
    function step(timestamp) {
      if (!startTime) startTime = timestamp;
      var progress = Math.min((timestamp - startTime) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      var current = Math.floor(eased * target);
      el.textContent = current;
      if (progress < 1) requestAnimationFrame(step);
      else el.textContent = target;
    }
    requestAnimationFrame(step);
  }

  var statsAnimated = false;
  function checkStats() {
    if (statsAnimated) return;
    var rect = document.getElementById('stats').getBoundingClientRect();
    if (rect.top < window.innerHeight - 60) {
      statsAnimated = true;
      animateValue(document.getElementById('sigCount'), SIG_COUNT);
      document.getElementById('verVal').textContent = 'VER_VAL';
      animateValue(document.getElementById('sizeVal'), SIZE_MB_VAL);
    }
  }

  document.querySelectorAll('.copy-cmd').forEach(function(el) {
    el.addEventListener('click', function() {
      var text = this.textContent.trim();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function() {
          el.classList.add('copied');
          setTimeout(function() { el.classList.remove('copied'); }, 1500);
        });
      } else {
        var ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('Copiado: ' + text);
      }
    });
  });

  function showToast(msg) {
    var t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    setTimeout(function() { t.classList.remove('show'); }, 2000);
  }

  var featureObserver = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) entry.target.classList.add('visible');
    });
  }, { threshold: 0.1 });

  document.querySelectorAll('.feature').forEach(function(f, i) {
    featureObserver.observe(f);
    f.style.transitionDelay = (i * 0.06) + 's';
  });

  window.addEventListener('scroll', function() {
    checkStats();
    var scrollBtn = document.getElementById('scrollTop');
    scrollBtn.classList.toggle('show', window.scrollY > 400);
    var st = window.scrollY;
    var hero = document.getElementById('hero');
    if (hero) {
      hero.style.transform = 'translateY(' + (st * 0.12) + 'px)';
      hero.style.opacity = Math.max(0, 1 - st / 500);
    }
  });

  document.getElementById('scrollTop').addEventListener('click', function() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  checkStats();

  document.getElementById('fileHash').textContent = FILE_HASH;
})();
</script>
</body>
</html>"""


def _get_package_hash():
    pkg_path = os.path.join(tempfile.gettempdir(), f"DefendR-{VERSION}.tar.gz")
    if not os.path.isfile(pkg_path):
        return "—"
    try:
        h = hashlib.sha256()
        with open(pkg_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "—"


def _build_page(sig_count, version, size_mb, date):
    page = _PAGE_RAW
    page = page.replace("FAVICON_PLACEHOLDER", FAVICON_SVG)
    page = page.replace("__SIG_COUNT__", str(sig_count))
    page = page.replace("__SIZE_MB__", str(size_mb))
    page = page.replace("VER_VAL", version)
    page = page.replace("DATE_VAL", date)
    page = page.replace("__SIZE_MB_TEXT__", str(size_mb))
    page = page.replace("__SIG_COUNT_TEXT__", str(sig_count))
    page = page.replace("HASH_VAL", _get_package_hash())
    return page




# ── Rate limiter / DoS protection ──────────────────────────────────────
_RATELIMIT = {}  # ip -> [timestamps]
_RLOCK = threading.Lock()
_RATE_MAX = 80       # max requests per window
_RATE_WIN = 10       # window in seconds
_BLOCKED_IPS = set()
_BLOCK_LOCK = threading.Lock()
_BLOCK_DURATION = 60  # seconds an IP stays blocked


def _check_rate_limit(ip):
    now = time.time()
    with _RLOCK:
        if ip in _BLOCKED_IPS:
            return False
        ts_list = _RATELIMIT.get(ip, [])
        # remove old entries
        cutoff = now - _RATE_WIN
        ts_list = [t for t in ts_list if t > cutoff]
        if len(ts_list) >= _RATE_MAX:
            with _BLOCK_LOCK:
                _BLOCKED_IPS.add(ip)
                threading.Timer(_BLOCK_DURATION, lambda: _BLOCKED_IPS.discard(ip)).start()
            return False
        ts_list.append(now)
        _RATELIMIT[ip] = ts_list
    return True


_ABUSIVE_AGENTS = re.compile(
    r"(nikto|sqlmap|nmap|masscan|xerxes|hydra|medusa|dirbuster|gobuster|wfuzz|"
    r"burpsuite|acunetix|nessus|openvas|zap|dotdotpwn|padbuster|wfuzz|"
    r"python-requests|python-urllib|go-http-client|curl|wget|libwww|perl|ruby)",
    re.I,
)

class DownloadHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self._build_package()
        super().__init__(*args, directory=tempfile.gettempdir(), **kwargs)

    @staticmethod
    def _build_package():
        pkg_path = os.path.join(tempfile.gettempdir(), f"DefendR-{VERSION}.tar.gz")
        if os.path.isfile(pkg_path):
            return
        EXCLUDE = {".git", "__pycache__"}
        def _filter(ti):
            parts = ti.name.replace("\\", "/").split("/")
            if any(p in EXCLUDE for p in parts):
                return None
            return ti
        with tarfile.open(pkg_path, "w:gz") as tar:
            tar.add(PROJECT_DIR, arcname="DefendR", filter=_filter)

    def _send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://fonts.googleapis.com https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "font-src https://fonts.gstatic.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;"
        )

    def do_GET(self):
        self._handle_request()

    def do_HEAD(self):
        self._handle_request(body=False)

    def _handle_request(self, body=True):
        ip = self.client_address[0]
        if not _check_rate_limit(ip):
            self.send_response(429)
            self._send_security_headers()
            self.send_header("Content-Type", "text/plain")
            self.send_header("Retry-After", "30")
            msg = b"Too many requests. Please slow down.\n"
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            if body:
                self.wfile.write(msg)
            return
        if self.path == "/":
            self.send_response(200)
            self._send_security_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(PAGE.encode("utf-8"))))
            self.end_headers()
            if body:
                self.wfile.write(PAGE.encode("utf-8"))
        elif self.path == "/download":
            pkg_path = os.path.join(tempfile.gettempdir(), f"DefendR-{VERSION}.tar.gz")
            if not os.path.isfile(pkg_path):
                self._build_package()
            if not os.path.isfile(pkg_path):
                self.send_error(404, "Package not found")
                return
            self.send_response(200)
            self._send_security_headers()
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Disposition",
                             f'attachment; filename="DefendR-{VERSION}.tar.gz"')
            sz = os.path.getsize(pkg_path)
            self.send_header("Content-Length", str(sz))
            self.end_headers()
            if body:
                with open(pkg_path, "rb") as f:
                    self.wfile.write(f.read())
        elif self.path == "/health":
            self.send_response(200)
            self._send_security_headers()
            self.send_header("Content-Type", "application/json")
            uptime = int(time.time() - START_TIME)
            data = f'{{"status":"ok","uptime":{uptime},"version":"{VERSION}","sigs":{SIG_COUNT}}}'
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if body:
                self.wfile.write(data.encode("utf-8"))
        else:
            self.send_response(404)
            self._send_security_headers()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            msg = b"404 - Pagina nao encontrada"
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            if body:
                self.wfile.write(msg)

    def log_message(self, format, *args):
        try:
            icon = "✓" if args[0] == "200" else "!"
            print(f"  [{icon}] {args[0]} {args[1]} {args[2]}")
        except IndexError:
            print(f"  [!] {' '.join(str(a) for a in args)}")


def _get_size():
    total = 0
    for root, dirs, files in os.walk(PROJECT_DIR):
        if "__pycache__" in root:
            continue
        for f in files:
            fp = os.path.join(root, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total


def _get_version():
    v = "2.0.0"
    try:
        from defendr.constants import __version__ as ver
        v = ver
    except Exception:
        pass
    return v


def _get_package_path():
    return os.path.join(tempfile.gettempdir(), f"DefendR-{VERSION}.tar.gz")


def _get_ips():
    import socket
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips


VERSION = _get_version()
TOTAL_SIZE = _get_size()
SIZE_MB = round(TOTAL_SIZE / (1024 * 1024), 1)
_ips = _get_ips()
IP = _ips[0] if _ips else "127.0.0.1"
DATE = __import__("datetime").datetime.now().strftime("%d/%m/%Y")


def _count_patterns():
    try:
        from defendr.engine import DefendREngine
        e = DefendREngine()
        return len(e.malware_patterns) + len(e._clamav_patterns) + len(e._remote_patterns) + len(e.suspicious_strings)
    except Exception:
        return 0


SIG_COUNT = _count_patterns()

PAGE = _build_page(SIG_COUNT, VERSION, SIZE_MB, DATE)


def start(host=HOST, port=PORT):
    server = HTTPServer((host, port), DownloadHandler)
    print(f"\n  🛡️  Servidor DefendR rodando em:")
    print(f"  ┌──────────────────────────────────────────┐")
    print(f"  │  Local:    http://{host}:{port}                 │")
    for addr in _get_ips():
        print(f"  │  Rede:     http://{addr}:{port}               │")
    print(f"  │  Health:   http://{host}:{port}/health        │")
    print(f"  └──────────────────────────────────────────┘")
    print(f"  Pressione Ctrl+C para parar\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Servidor encerrado.")
        server.server_close()


def _get_ips():
    import socket
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips


if __name__ == "__main__":
    start()
