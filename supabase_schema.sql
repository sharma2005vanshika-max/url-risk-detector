-- ========================================================
-- AegisGuard URL Risk Detector - Supabase Schema
-- Run this in your Supabase Dashboard: SQL Editor -> New Query -> Run
-- ========================================================

-- 1. Create the scan_logs table
CREATE TABLE IF NOT EXISTS public.scan_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    hostname TEXT,
    root_domain TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'Safe',
    risk_color TEXT DEFAULT 'emerald',
    tld TEXT,
    protocol TEXT DEFAULT 'http',
    threat_count INTEGER DEFAULT 0,
    threats JSONB DEFAULT '[]'::jsonb,
    targeted_brand TEXT,
    dns_resolved BOOLEAN DEFAULT false,
    ssl_valid BOOLEAN DEFAULT false,
    user_ip TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Create indexes for fast querying & analytics
CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON public.scan_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_logs_risk_level ON public.scan_logs (risk_level);
CREATE INDEX IF NOT EXISTS idx_scan_logs_root_domain ON public.scan_logs (root_domain);
CREATE INDEX IF NOT EXISTS idx_scan_logs_targeted_brand ON public.scan_logs (targeted_brand) WHERE targeted_brand IS NOT NULL;

-- 3. Enable Row Level Security (RLS)
ALTER TABLE public.scan_logs ENABLE ROW LEVEL SECURITY;

-- 4. Policies: Allow public read and insert for the scanner API
DROP POLICY IF EXISTS "Allow public insert to scan_logs" ON public.scan_logs;
CREATE POLICY "Allow public insert to scan_logs"
    ON public.scan_logs
    FOR INSERT
    TO public, anon, authenticated
    WITH CHECK (true);

DROP POLICY IF EXISTS "Allow public read of scan_logs" ON public.scan_logs;
CREATE POLICY "Allow public read of scan_logs"
    ON public.scan_logs
    FOR SELECT
    TO public, anon, authenticated
    USING (true);
