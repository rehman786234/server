-- 1) videos table: uploader + creator fields
ALTER TABLE videos
  ADD COLUMN IF NOT EXISTS user_id     INT REFERENCES mydata(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '',
  ADD COLUMN IF NOT EXISTS visibility  VARCHAR(10) NOT NULL DEFAULT 'public', -- public | unlisted | private
  ADD COLUMN IF NOT EXISTS video_type  VARCHAR(10) NOT NULL DEFAULT 'long',
  ADD COLUMN IF NOT EXISTS duration    INT DEFAULT 0,                          -- seconds
  ADD COLUMN IF NOT EXISTS file_size   BIGINT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS views       INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS video_quality VARCHAR(40) NOT NULL DEFAULT 'Original',
  ADD COLUMN IF NOT EXISTS qualities   JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMP DEFAULT NOW();
ALTER TABLE mydata
  ADD COLUMN IF NOT EXISTS account_status VARCHAR(12) NOT NULL DEFAULT 'active';
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'videos_video_type_check'
      AND conrelid = 'videos'::regclass
  ) THEN
    ALTER TABLE videos
      ADD CONSTRAINT videos_video_type_check CHECK (video_type IN ('short', 'long'));
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_videos_user ON videos(user_id);

-- API-key usage tracking is written by validate_api_key() before premium-feed access.
ALTER TABLE apikeys
  ADD COLUMN IF NOT EXISTS request_count BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS api_usage (
  id         BIGSERIAL PRIMARY KEY,
  api_key_id INT NOT NULL REFERENCES apikeys(id) ON DELETE CASCADE,
  user_id    INT NOT NULL REFERENCES mydata(id) ON DELETE CASCADE,
  endpoint   TEXT NOT NULL,
  method     VARCHAR(10) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_usage_user_created
  ON api_usage(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_usage_key
  ON api_usage(api_key_id);

-- 2) channels: one per user (uploader profile)
CREATE TABLE IF NOT EXISTS channels (
  id           SERIAL PRIMARY KEY,
  user_id      INT UNIQUE NOT NULL REFERENCES mydata(id) ON DELETE CASCADE,
  channel_name VARCHAR(100) NOT NULL,
  handle       VARCHAR(50) UNIQUE,
  avatar_url   TEXT,
  description  TEXT DEFAULT '',
  created_at   TIMESTAMP DEFAULT NOW()
);
ALTER TABLE channels
  ADD COLUMN IF NOT EXISTS banner_url TEXT,
  ADD COLUMN IF NOT EXISTS moderation_status VARCHAR(12) NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT FALSE;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'mydata_account_status_check'
      AND conrelid = 'mydata'::regclass
  ) THEN
    ALTER TABLE mydata ADD CONSTRAINT mydata_account_status_check
      CHECK (account_status IN ('active', 'suspended', 'banned'));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'channels_moderation_status_check'
      AND conrelid = 'channels'::regclass
  ) THEN
    ALTER TABLE channels ADD CONSTRAINT channels_moderation_status_check
      CHECK (moderation_status IN ('active', 'suspended', 'banned'));
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_channels_moderation_status
  ON channels(moderation_status, id DESC);

-- 3) video_views: for analytics (views per day)
CREATE TABLE IF NOT EXISTS video_views (
  id        BIGSERIAL PRIMARY KEY,
  video_id  INT NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  viewer_id INT REFERENCES mydata(id) ON DELETE SET NULL,
  viewed_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_views_video ON video_views(video_id, viewed_at);

-- Google sign-in and short-lived, single-use password reset codes.
ALTER TABLE mydata ADD COLUMN IF NOT EXISTS google_sub TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_mydata_google_sub
  ON mydata(google_sub) WHERE google_sub IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mydata_lower_email ON mydata(LOWER(email));

CREATE TABLE IF NOT EXISTS password_reset_otps (
  email       TEXT PRIMARY KEY,
  otp_hash    TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  attempts    SMALLINT NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 5),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_password_reset_otps_expiry
  ON password_reset_otps(expires_at);

CREATE TABLE IF NOT EXISTS site_settings (
  id                   SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  maintenance_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
  maintenance_message TEXT NOT NULL DEFAULT '',
  terms_text           TEXT NOT NULL DEFAULT '',
  terms_version        INTEGER NOT NULL DEFAULT 1 CHECK (terms_version > 0),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO site_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS cloudinary_accounts (
  account_key          VARCHAR(20) PRIMARY KEY CHECK (account_key IN ('videos', 'media')),
  cloud_name           VARCHAR(100) NOT NULL,
  api_key              VARCHAR(128) NOT NULL DEFAULT '',
  api_secret_encrypted TEXT,
  upload_preset        VARCHAR(100) NOT NULL DEFAULT '',
  enabled              BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS playlists_v2 (
  id          SERIAL PRIMARY KEY,
  user_id     INT NOT NULL REFERENCES mydata(id) ON DELETE CASCADE,
  title       VARCHAR(150) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  thumbnail   TEXT,
  visibility  VARCHAR(10) NOT NULL DEFAULT 'private'
              CHECK (visibility IN ('public', 'unlisted', 'private')),
  is_premium  BOOLEAN NOT NULL DEFAULT FALSE,
  is_system   BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE playlists_v2
  ADD COLUMN IF NOT EXISTS is_premium BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_playlists_v2_user_updated
  ON playlists_v2(user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS playlist_items (
  id          BIGSERIAL PRIMARY KEY,
  playlist_id INT NOT NULL REFERENCES playlists_v2(id) ON DELETE CASCADE,
  video_id    INT NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
  position    INT NOT NULL DEFAULT 0,
  added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (playlist_id, video_id)
);
CREATE INDEX IF NOT EXISTS idx_playlist_items_order
  ON playlist_items(playlist_id, position, added_at);
