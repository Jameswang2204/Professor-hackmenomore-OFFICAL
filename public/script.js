// public/script.js
// Unified Chat, URL Checker, Quiz Modules, and Cyber News Widget

document.addEventListener('DOMContentLoaded', () => {
  // Element references
  const chatForm       = document.getElementById('chatForm');
  const chatInput      = document.getElementById('chatInput');
  const chatWindow     = document.getElementById('chatWindow');
  const urlCheckerForm = document.getElementById('urlCheckerForm');
  const urlInput       = document.getElementById('urlInput');
  const urlResult      = document.getElementById('urlResult');
  const sendButton     = chatForm.querySelector('button');

  // --- Utility functions ---
  function sanitize(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
  function appendMessage(sender, html) {
    const msg = document.createElement('div');
    msg.className = `mb-2 ${sender === 'user' ? 'text-right' : 'text-left'}`;
    msg.innerHTML = `<span class="inline-block px-3 py-2 rounded ${
      sender === 'user' ? 'bg-green-200' : 'bg-gray-200'
    }">${html}</span>`;
    chatWindow.appendChild(msg);
    chatWindow.scrollTop = chatWindow.scrollHeight;
  }

  // --- Chat with OpenAI ---
  async function getBotResponse(message) {
    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const { reply } = await res.json();
      return reply;
    } catch (err) {
      console.error('Chat fetch error:', err);
      return '⚠️ Sorry, something went wrong.';
    }
  }
  chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = chatInput.value.trim();
    if (!text) return;
    appendMessage('user', sanitize(text));
    chatInput.value = '';
    chatInput.disabled = true;
    sendButton.disabled = true;
    const origHTML = sendButton.innerHTML;
    sendButton.innerHTML =
      '<div class="animate-spin h-5 w-5 border-2 border-t-2 border-white rounded-full mx-auto"></div>';
    const reply = await getBotResponse(text);
    chatInput.disabled = false;
    sendButton.disabled = false;
    sendButton.innerHTML = origHTML;
    appendMessage('bot', sanitize(reply));
  });

  // --- URL Checker ---
  urlCheckerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) {
      urlResult.textContent = 'Please enter a URL.';
      return;
    }
    try { new URL(url); }
    catch {
      urlResult.textContent = 'Invalid URL format.';
      return;
    }
    urlResult.textContent = '🔍 Checking URL…';
    try {
      const res = await fetch('/api/check-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const { verdict } = await res.json();
      let msg = '';
      if (verdict === 'malicious') {
        msg = `🔗 The URL <strong>${sanitize(url)}</strong> is <span class="font-bold text-red-600">Malicious ⚠️</span>`;
      } else if (verdict === 'safe') {
        msg = `🔗 The URL <strong>${sanitize(url)}</strong> appears Safe ✅`;
      } else {
        msg = `🔗 The URL <strong>${sanitize(url)}</strong> status is Unknown ❓`;
      }
      appendMessage('bot', msg);
    } catch (err) {
      console.error('URL-check fetch failed:', err);
      appendMessage('bot', '⚠️ Failed to check URL. Try again later.');
    } finally {
      urlResult.textContent = '';
    }
  });

  // --- Quiz Modules ---
  const quizModules = {
    phishing: {
      title: "Phishing",
      intro: `Phishing is a cyberattack that tricks you into giving away private information like passwords or credit card numbers. These attacks usually arrive as emails or messages that look like they’re from someone you trust—like your bank, a coworker, or a popular website. The goal is to get you to click a link, download an attachment, or fill out a fake login form.`,
      questions: [
        { text: "What is the main goal of phishing?", choices: ["Speed up your device","Trick you into revealing sensitive information","Fix software bugs","Install official updates"], answer: 1 },
        { text: "What does a phishing email often try to do?",   choices: ["Encourage healthy habits","Offer financial advice","Get you to click a malicious link or download an attachment","Teach you to code"], answer: 2 },
        { text: "Which of these could be a phishing attempt?", choices: ["A friend sending you a photo","An unknown email asking you to 'verify your password immediately'","A subscription reminder for a service you use","A weather alert"], answer: 1 },
        { text: "How can you spot a phishing scam?",            choices: ["It has perfect grammar","It offers a job promotion","It asks for urgent action and personal information","It always comes on Friday"], answer: 2 },
        { text: "What should you do if you suspect a phishing message?", choices: ["Forward it to friends","Click the link to see what it is","Report it to IT or security team","Respond and ask if it's real"], answer: 2 }
      ]
    },

    password: {
      title: "Password Safety",
      intro: `Your password is the key to your digital identity. Use strong, unique passwords for every account to stay protected. A good password includes a mix of uppercase and lowercase letters, numbers, and special characters. Never reuse passwords, and avoid personal details like your name or birthday.`,
      questions: [
        { text: "Which of the following is a strong password?", choices: ["iloveyou","password123","Z3!kR7mP#1","james1999"], answer: 2 },
        { text: "Why avoid personal info in a password?",       choices: ["It’s easier to remember","It’s too long","Hackers can guess it easily","It’s required by most sites"], answer: 2 },
        { text: "What does it mean to 'reuse a password'?",     choices: ["Using the same password for multiple accounts","Resetting monthly","Saving in a browser","Sharing with friends"], answer: 0 },
        { text: "Recommended password practice?",              choices: ["Keep it short","Change every few years","Use a password manager","Use the same everywhere"], answer: 2 },
        { text: "Major risk of weak passwords?",               choices: ["Low battery","Unauthorized access","Slower Wi-Fi","Legal trouble"], answer: 1 }
      ]
    },

    mfa: {
      title: "Multi-Factor Authentication",
      intro: `Multi-Factor Authentication (MFA) adds a second layer of protection beyond passwords—like OTP codes, authenticator apps, or hardware tokens. Even if a thief steals your password, they can’t get in without that second factor.`,
      questions: [
        { text: "What does MFA stand for?",                    choices: ["Multi-Factor Authentication","Managed File Access","Mobile Firewall Account","Multiple File Applications"], answer: 0 },
        { text: "Example of a second factor?",                  choices: ["PIN in a text file","Browser extension","Code sent to your phone","Security question only"], answer: 2 },
        { text: "Why is MFA effective?",                       choices: ["Replaces passwords","Organizes emails","Stops logins if password stolen","Speeds up websites"], answer: 2 },
        { text: "Which is NOT an MFA factor?",                 choices: ["Something you know","Something you have","Something you are","Something you heard"], answer: 3 },
        { text: "If you lose your phone (MFA factor)?",         choices: ["MFA useless","Locked out forever","Recover via backup methods","Must create new account"], answer: 2 }
      ]
    },

    social: {
      title: "Social Engineering",
      intro: `Social engineering exploits trust—attackers pretend to be coworkers, IT staff, or executives to trick you into revealing data or granting access. It’s about manipulating human behavior rather than hacking code.`,
      questions: [
        { text: "Social engineering relies on…",                choices: ["Server firewalls","Hacking devices","Human psychology and trust","Advanced encryption"], answer: 2 },
        { text: "Common tactic is…",                            choices: ["Software update emails","Phone call from ‘IT support’","Router resets","Pop-up blockers"], answer: 1 },
        { text: "Prevention technique?",                         choices: ["Never turn off PC","Keep passwords in notebook","Verify identity of requesters","Always trust company emails"], answer: 2 },
        { text: "Why is it so effective?",                       choices: ["Fast internet","Unverified trust","Complex coding","High-end devices"], answer: 1 },
        { text: "If pressured for credentials, you should…",      choices: ["Give them if urgent","Call IT/security","Ignore it","Change your password"], answer: 1 }
      ]
    },

    browsing: {
      title: "Secure Browsing",
      intro: `Secure browsing means checking for HTTPS, avoiding shady links, keeping your browser up to date, and using security tools (antivirus, ad-blockers) to guard against drive-by downloads and exploits.`,
      questions: [
        { text: "HTTPS in URL means…",                          choices: ["Foreign site","Has ads","Secure connection","Fake website"], answer: 2 },
        { text: "Sign of unsafe site?",                          choices: ["Padlock icon","Starts with https","Misspellings/pop-ups","Loads fast"], answer: 2 },
        { text: "Safe browsing habit?",                          choices: ["Click unknown links","Visit random sites","Keep browser updated","Disable security features"], answer: 2 },
        { text: "Before downloading a file…",                    choices: ["Check size","See if interesting","Verify trusted source","Ignore warnings"], answer: 2 },
        { text: "Tool that protects while browsing?",            choices: ["Screenshot app","Calendar","Antivirus software","Music player"], answer: 2 }
      ]
    }
  };

  let currentQuiz = null, currentIndex = 0, currentScore = 0;

  function renderQuizMessage(html) {
    appendMessage('bot', html);
  }

  function startQuiz(key) {
    currentQuiz = quizModules[key];
    currentIndex = 0;
    currentScore = 0;
    chatWindow.innerHTML = '';
    renderQuizMessage(`<strong>${currentQuiz.title}</strong><br>${sanitize(currentQuiz.intro)}`);
    setTimeout(askQuizQuestion, 500);
  }

  function askQuizQuestion() {
    const q = currentQuiz.questions[currentIndex];
    let html = `<p class="font-semibold mb-1">Q${currentIndex+1}: ${sanitize(q.text)}</p><div class="space-x-2">`;
    q.choices.forEach((c,i) => {
      html += `<button class="quiz-choice bg-blue-500 text-white px-3 py-1 rounded" data-index="${i}">${String.fromCharCode(65+i)}. ${sanitize(c)}</button>`;
    });
    html += '</div>';
    renderQuizMessage(html);
    document.querySelectorAll('.quiz-choice').forEach(btn =>
      btn.addEventListener('click', () => handleQuizAnswer(btn))
    );
  }

  function handleQuizAnswer(button) {
    const sel = +button.dataset.index;
    const ans = currentQuiz.questions[currentIndex].answer;
    document.querySelectorAll('.quiz-choice').forEach(b => b.disabled = true);
    if (sel === ans) {
      currentScore++;
      renderQuizMessage('✅ Correct!');
    } else {
      renderQuizMessage(`❌ Wrong. Answer was ${String.fromCharCode(65+ans)}.`);
    }
    currentIndex++;
    if (currentIndex < currentQuiz.questions.length) {
      setTimeout(askQuizQuestion, 800);
    } else {
      setTimeout(() =>
        renderQuizMessage(`<strong>Done!</strong> You scored ${currentScore}/${currentQuiz.questions.length}.`),
        800
      );
    }
  }

  document.querySelectorAll('[data-module]').forEach(btn =>
    btn.addEventListener('click', () => {
      const key = btn.dataset.module;
      if (quizModules[key]) startQuiz(key);
    })
  );

  // --- Cyber News Widget (TheHackerNews) ---
  async function loadCyberNews() {
    try {
      const res = await fetch(
        'https://api.allorigins.win/raw?url=https://feeds.feedburner.com/TheHackersNews'
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const xmlText = await res.text();
      const parser = new DOMParser();
      const xml    = parser.parseFromString(xmlText, 'application/xml');
      const items  = Array.from(xml.querySelectorAll('item')).slice(0, 5);
      const html   = items.map(item => {
        const title = item.querySelector('title')?.textContent || 'No title';
        const link  = item.querySelector('link')?.textContent || '#';
        return `<li class="mb-1"><a href="${link}" target="_blank" class="text-blue-600 hover:underline">${sanitize(title)}</a></li>`;
      }).join('');
      document.getElementById('newsContent').innerHTML =
        `<ul class="list-disc pl-5">${html}</ul>`;
    } catch (err) {
      console.error('News load error:', err);
      document.getElementById('newsContent').textContent =
        '⚠️ Could not load news right now.';
    }
  }
  loadCyberNews();

});