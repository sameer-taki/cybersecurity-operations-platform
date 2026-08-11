DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') THEN
    CREATE ROLE app_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'platform_admin') THEN
    CREATE ROLE platform_admin NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_api_login') THEN
    CREATE ROLE app_api_login LOGIN PASSWORD 'app_runtime' NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'platform_admin_login') THEN
    CREATE ROLE platform_admin_login LOGIN PASSWORD 'platform_admin' NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT app_runtime TO app_api_login;
GRANT platform_admin TO platform_admin_login;
