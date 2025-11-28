let currentCategory = "";
let currentLevel = "";
let currentQuestionIndex = 0;
let score = 0;
let userName = "";
let startTime;
let shuffledQuestions = [];

// Shuffle helper
function shuffleArray(array) {
  for (let i = array.length -1; i>0; i--) {
    const j = Math.floor(Math.random()*(i+1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

// Start quiz from selections
function startSelectedQuiz() {
  userName = document.getElementById("userName").value.trim();
  const category = document.getElementById("categorySelect").value;
  const level = document.getElementById("levelSelect").value;

  if(!userName){ alert("Enter your name!"); return; }
  if(!category){ alert("Select a category!"); return; }
  if(!level){ alert("Select a difficulty level!"); return; }

  startQuiz(category, level);
}

// Initialize quiz
function startQuiz(category, level) {
  currentCategory = category;
  currentLevel = level;
  currentQuestionIndex = 0;
  score = 0;
  startTime = new Date();

  shuffledQuestions = shuffleArray(
    questions[currentCategory].filter(q => q.level === currentLevel)
  );

  document.getElementById("home").classList.add("hidden");
  document.getElementById("quiz").classList.remove("hidden");

  showQuestion();
  startTimer();
}

// Show question
function showQuestion() {
  const q = shuffledQuestions[currentQuestionIndex];
  document.getElementById("question").innerText = q.question;

  const optionsDiv = document.getElementById("options");
  optionsDiv.innerHTML = "";

  q.options.forEach((opt, idx) => {
    const btn = document.createElement("button");
    btn.innerText = opt;
    btn.onclick = () => checkAnswer(idx);
    optionsDiv.appendChild(btn);
  });

  // Animate options
  setTimeout(()=> {
    document.querySelectorAll("#options button").forEach((b,i)=>{
      b.style.animationDelay = `${i*0.05}s`;
      b.style.opacity = 1;
    });
  },10);

  document.getElementById("nextBtn").style.display = "none";

  // Update progress
  const progressPercent = ((currentQuestionIndex)/shuffledQuestions.length)*100;
  document.getElementById("progress").style.width = `${progressPercent}%`;
}

// Check answer
function checkAnswer(selectedIndex) {
  const q = shuffledQuestions[currentQuestionIndex];
  if(selectedIndex === q.answer) score++;

  document.querySelectorAll("#options button").forEach((btn, idx) => {
    btn.disabled = true;
    if(idx===q.answer){ btn.style.background="#28a745"; btn.style.color="#fff"; }
    else if(idx===selectedIndex){ btn.style.background="#dc3545"; btn.style.color="#fff"; }
  });

  document.getElementById("nextBtn").style.display="block";
}

// Next question
function nextQuestion() {
  currentQuestionIndex++;
  if(currentQuestionIndex < shuffledQuestions.length) showQuestion();
  else showResult();
}

// Timer
let timerInterval;
function startTimer() {
  const timerEl = document.getElementById("timer");
  clearInterval(timerInterval);
  timerInterval = setInterval(()=>{
    const elapsed = Math.floor((new Date() - startTime)/1000);
    const mins = Math.floor(elapsed/60);
    const secs = elapsed % 60;
    timerEl.innerText = `Time: ${mins}:${secs<10?'0':''}${secs}`;
  },500);
}

// Show result
function showResult() {
  document.getElementById("quiz").classList.add("hidden");
  document.getElementById("result").classList.remove("hidden");
  clearInterval(timerInterval);

  const totalTime = Math.floor((new Date() - startTime)/1000);
  const mins = Math.floor(totalTime/60);
  const secs = totalTime%60;

  document.getElementById("score").innerText = `${userName}, you scored ${score} out of ${shuffledQuestions.length}`;

  const percentage = (score/shuffledQuestions.length)*100;
  let msg = percentage===100?"Excellent! Perfect score!":percentage>=60?"Great job! You did well.":"Needs improvement. Keep practicing!";
  document.getElementById("message").innerText = msg;
  document.getElementById("personalNote").innerText = `Time taken: ${mins}:${secs<10?'0':''}${secs}`;

  // Fill progress bar completely
  document.getElementById("progress").style.width = `100%`;
}

// Go home
function goHome() {
  document.getElementById("result").classList.add("hidden");
  document.getElementById("home").classList.remove("hidden");
}

// Theme toggle
document.getElementById("themeBtn").addEventListener("click", () => {
  const body = document.body;
  if(body.classList.contains("dark")) {
    body.classList.remove("dark");
    body.classList.add("light");
    document.getElementById("themeBtn").innerText = "☀️";
  } else {
    body.classList.remove("light");
    body.classList.add("dark");
    document.getElementById("themeBtn").innerText = "🌙";
  }
});
