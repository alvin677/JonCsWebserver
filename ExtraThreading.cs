using Microsoft.Extensions.Hosting;

namespace WebServer
{
    public class BackgroundTaskQueue
    {
        private readonly SemaphoreSlim _signal = new SemaphoreSlim(0);
        private readonly Queue<Func<CancellationToken, Task>> _tasks = new Queue<Func<CancellationToken, Task>>();

        public void Enqueue(Func<CancellationToken, Task> task)
        {
            if (task == null) throw new ArgumentNullException(nameof(task));
            lock (_tasks)
            {
                _tasks.Enqueue(task);
            }
            _signal.Release();
        }

        public async Task<Func<CancellationToken, Task>> DequeueAsync(CancellationToken cancellationToken)
        {
            await _signal.WaitAsync(cancellationToken);
            lock (_tasks)
            {
                return _tasks.Dequeue();
            }
        }
    }

    // Worker Service
    public class Worker : BackgroundService
    {
        private readonly BackgroundTaskQueue _taskQueue;

        public Worker(BackgroundTaskQueue taskQueue)
        {
            _taskQueue = taskQueue;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var task = await _taskQueue.DequeueAsync(stoppingToken);
                await task(stoppingToken);
            }
        }
    }
}
