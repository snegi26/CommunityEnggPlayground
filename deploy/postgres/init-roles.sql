-- Two roles per KTD5: migrations run as the table owner; the app runs as a
-- non-owner role without BYPASSRLS so row-level security always applies.
CREATE ROLE passport_owner LOGIN PASSWORD 'owner' CREATEDB;
CREATE ROLE passport_app LOGIN PASSWORD 'app' NOSUPERUSER NOBYPASSRLS;
CREATE DATABASE passport OWNER passport_owner;
