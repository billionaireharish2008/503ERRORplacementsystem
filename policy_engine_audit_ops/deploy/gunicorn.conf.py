# Gunicorn: request limits and timeouts. Run behind nginx (TLS terminates there). Bind to localhost/socket only.
bind = "unix:/run/nfsu/gunicorn.sock"
workers = 3
worker_class = "gthread"
threads = 2
timeout = 30                 # kill hung workers
graceful_timeout = 30
keepalive = 5
max_requests = 1000          # recycle workers (memory leaks, long-lived state)
max_requests_jitter = 100
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190
forwarded_allow_ips = "127.0.0.1"   # only the local nginx may set X-Forwarded-*
accesslog = "-"
errorlog = "-"
access_log_format = '%(h)s %(l)s %(t)s "%(r)s" %(s)s %(b)s %(L)s'   # no query string with tokens: use %(U)s if needed
