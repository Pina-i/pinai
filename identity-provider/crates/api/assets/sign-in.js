// The pages' only script, served from here so the CSP allows no other: a form on its way shows
// it, and can't be sent twice. Disabled after the submit event, the button doesn't stop the send.
for (const form of document.querySelectorAll("form")) {
    form.addEventListener("submit", (event) => {
        const button = event.submitter ?? form.querySelector("button[type=submit]")
        if (!button) return
        if (button.classList.contains("is-busy")) {
            event.preventDefault()
            return
        }
        button.classList.add("is-busy")
        button.setAttribute("aria-busy", "true")
        setTimeout(() => {
            button.disabled = true
        })
    })
}

// A page brought back from the back-forward cache is ready to send again.
window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return
    for (const button of document.querySelectorAll("button.is-busy")) {
        button.classList.remove("is-busy")
        button.removeAttribute("aria-busy")
        button.disabled = false
    }
})

// "Forgot password?" folds the Sign in tab into the reset request, and "← Sign in" back, in place:
// the address typed stays. Each link opens the same state as a page of its own without script.
const view = document.querySelector("[data-view]")
const folding = view?.querySelector("form[data-forgot]")
if (view && folding) {
    const email = folding.querySelector("#email")
    const password = folding.querySelector("#password")
    for (const link of view.querySelectorAll("a[data-to]")) {
        link.addEventListener("click", (event) => {
            if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
            event.preventDefault()
            const forgot = link.dataset.to === "forgot"
            view.dataset.view = link.dataset.to
            folding.action = forgot ? folding.dataset.forgot : folding.dataset.signIn
            // Disabled, the password is neither required nor sent with the request.
            password.disabled = forgot
            history.replaceState(null, "", link.href)
            document.title = forgot ? view.dataset.forgotTitle : view.dataset.signInTitle
            ;(forgot || !email.value ? email : password).focus()
        })
    }
}

// A new password's strength: a hint only. Under 8 characters the instance refuses it, so it shows
// as weak whatever else it holds.
const grade = (password) =>
    Math.min(
        password.length < 8 ? 1 : 4,
        (password.length >= 8) +
            (password.length >= 12) +
            /[A-Z]/.test(password) +
            /[^A-Za-z0-9]/.test(password) +
            /\d/.test(password),
    )
for (const meter of document.querySelectorAll(".meter[data-for]")) {
    const input = document.getElementById(meter.dataset.for)
    input?.addEventListener("input", () => {
        meter.dataset.score = input.value ? String(grade(input.value)) : "0"
    })
}
for (const repeat of document.querySelectorAll("input[data-repeats]")) {
    const first = document.getElementById(repeat.dataset.repeats)
    if (!first) continue
    const mark = () =>
        repeat.closest(".field")?.classList.toggle("field--ok", repeat.value !== "" && repeat.value === first.value)
    repeat.addEventListener("input", mark)
    first.addEventListener("input", mark)
}
