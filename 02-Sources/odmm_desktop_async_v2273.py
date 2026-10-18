"""Background network requests; marshal all GUI changes onto Tk main thread."""
from concurrent.futures import ThreadPoolExecutor

class AsyncReader:
    def __init__(self, scheduler, workers=2):
        self.scheduler = scheduler
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='odmm-read')
        self.generation = 0
        self.closed = False

    def invalidate(self):
        self.generation += 1

    def submit(self, work, on_success, on_error):
        if self.closed:
            return False
        self.invalidate()
        generation = self.generation
        future = self.pool.submit(work)
        def complete(done):
            try:
                result, error = done.result(), None
            except Exception as exc:
                result, error = None, type(exc).__name__
            # Tk callbacks must be invoked from main thread. Never call Tk.after
            # from the worker; scheduler is a thread-safe queue drained by Tk.
            self.scheduler.put((generation, on_success, on_error, result, error))
        future.add_done_callback(complete)
        return True

    def drain(self):
        while True:
            try:
                generation, success, failure, result, error = self.scheduler.get_nowait()
            except __import__('queue').Empty:
                break
            if not self.closed and generation == self.generation:
                (failure(error) if error else success(result))

    def close(self):
        self.closed = True
        self.invalidate()
        self.pool.shutdown(wait=False, cancel_futures=True)
