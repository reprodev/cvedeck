"""Built-in access control for the dashboard and API (Req 16).

- :mod:`.passwords` -- scrypt password hashing and the password policy.
- :mod:`.tokens`    -- random session and API tokens, and how they are hashed.
- :mod:`.service`   -- accounts, sessions, tokens and the first-run setup code.
- :mod:`.throttle`  -- backing off repeated failed logins.
- :mod:`.dependencies` -- the FastAPI dependency every protected router uses.
- :mod:`.cli`       -- ``cvedeck-admin``, for recovering a locked-out instance.
"""
