// A scan whose text recognition is still running settles by itself: poll the
// status endpoint the page carries and reload once it is no longer busy.
(function () {
  var url = document.body.dataset.status;
  if (!url) return;
  function poll() {
    fetch(url, { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (d && d.status !== "pending" && d.status !== "processing") location.reload();
        else setTimeout(poll, 3000);
      })
      .catch(function () { setTimeout(poll, 5000); });
  }
  setTimeout(poll, 3000);
})();
