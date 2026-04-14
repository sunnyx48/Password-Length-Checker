const passwordInput = document.getElementById("password");
const togglePasswordBtn = document.getElementById("togglePassword");
const checkBtn = document.getElementById("checkBtn");
const DEFAULT_MIN_LENGTH = 8;

const resultBox = document.getElementById("result");
const enteredLengthEl = document.getElementById("enteredLength");
const statusEl = document.getElementById("status");
const messageEl = document.getElementById("message");

function checkPasswordPolicy(password) {
  const length = password.length;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasSpecialChar = /[^A-Za-z0-9]/.test(password);
  const hasNumber = /\d/.test(password);

  const lengthOk = length >= DEFAULT_MIN_LENGTH;
  const passed =
    lengthOk && hasUppercase && hasLowercase && hasSpecialChar && hasNumber;

  let failMessage = "FAIL: Password does not meet required policy.";
  if (!hasUppercase && hasLowercase) {
    failMessage = "Add uppercase letter.";
  } else if (hasUppercase && hasLowercase && !hasSpecialChar) {
    failMessage = "Add special character.";
  } else if (!hasNumber) {
    failMessage = "Add number.";
  } else if (!lengthOk) {
    failMessage = `Password length should be at least ${DEFAULT_MIN_LENGTH}.`;
  }

  return {
    length,
    passed,
    message: passed
      ? `PASS: Password meets length, letter-case, and special-character policy.`
      : failMessage
  };
}

togglePasswordBtn.addEventListener("click", () => {
  const showing = passwordInput.type === "text";
  passwordInput.type = showing ? "password" : "text";
  togglePasswordBtn.innerHTML = showing ? "&#128065;" : "&#128584;";
  togglePasswordBtn.setAttribute(
    "aria-label",
    showing ? "Show password" : "Hide password"
  );
  togglePasswordBtn.setAttribute(
    "title",
    showing ? "Show password" : "Hide password"
  );
});

checkBtn.addEventListener("click", () => {
  const password = passwordInput.value;
  const result = checkPasswordPolicy(password);

  enteredLengthEl.textContent = result.length;
  statusEl.textContent = result.passed ? "PASS" : "FAIL";
  statusEl.className = result.passed ? "pass" : "fail";
  messageEl.textContent = result.message;

  resultBox.classList.remove("hidden");
});