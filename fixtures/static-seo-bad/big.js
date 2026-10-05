// Render-blocking script in <head> without defer/async.
window.analyticsQueue = [];
for (var i = 0; i < 1000; i++) { window.analyticsQueue.push(i); }
