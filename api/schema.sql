-- ============================================================
-- GreenBuck Database Schema
-- Creates the three tables used by the backend:
--   users        - accounts (with role for admin/user access)
--   transactions - financial transaction records
--   timing_log   - per-request research metadata (primary dataset)
--
-- Usage:
--   createdb greenbuck
--   psql greenbuck < schema.sql
-- ============================================================

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET row_security = off;

SET default_tablespace = '';
SET default_table_access_method = heap;

-- ============================================================
-- Table: users
-- ============================================================
CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(50) NOT NULL,
    password_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    role character varying(20) DEFAULT 'user'::character varying NOT NULL
);

ALTER TABLE public.users OWNER TO postgres;

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.users_id_seq OWNER TO postgres;
ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);

-- ============================================================
-- Table: transactions
-- ============================================================
CREATE TABLE public.transactions (
    id integer NOT NULL,
    amount numeric(10,2) NOT NULL,
    category character varying(50) NOT NULL,
    "timestamp" character varying(30) NOT NULL,
    merchant character varying(100)
);

ALTER TABLE public.transactions OWNER TO postgres;

CREATE SEQUENCE public.transactions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.transactions_id_seq OWNER TO postgres;
ALTER SEQUENCE public.transactions_id_seq OWNED BY public.transactions.id;
ALTER TABLE ONLY public.transactions ALTER COLUMN id SET DEFAULT nextval('public.transactions_id_seq'::regclass);

ALTER TABLE ONLY public.transactions
    ADD CONSTRAINT transactions_pkey PRIMARY KEY (id);

-- ============================================================
-- Table: timing_log  (primary research dataset)
-- ============================================================
CREATE TABLE public.timing_log (
    id integer NOT NULL,
    request_id character varying(36) NOT NULL,
    action_type character varying(50),
    platform character varying(20),
    encryption_mode character varying(20),
    mitigation_state character varying(20),
    receive_time timestamp with time zone NOT NULL,
    response_sent_time timestamp with time zone NOT NULL,
    duration_ms numeric(10,3),
    cpu_utilization numeric(5,2),
    endpoint character varying(100),
    status_code integer
);

ALTER TABLE public.timing_log OWNER TO postgres;

CREATE SEQUENCE public.timing_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.timing_log_id_seq OWNER TO postgres;
ALTER SEQUENCE public.timing_log_id_seq OWNED BY public.timing_log.id;
ALTER TABLE ONLY public.timing_log ALTER COLUMN id SET DEFAULT nextval('public.timing_log_id_seq'::regclass);

ALTER TABLE ONLY public.timing_log
    ADD CONSTRAINT timing_log_pkey PRIMARY KEY (id);

-- ============================================================
-- Permissions: grant access to the application database user
-- ============================================================
GRANT ALL ON TABLE public.users TO greenbuck_user;
GRANT ALL ON SEQUENCE public.users_id_seq TO greenbuck_user;
GRANT ALL ON TABLE public.transactions TO greenbuck_user;
GRANT ALL ON SEQUENCE public.transactions_id_seq TO greenbuck_user;
GRANT ALL ON TABLE public.timing_log TO greenbuck_user;
GRANT ALL ON SEQUENCE public.timing_log_id_seq TO greenbuck_user;
