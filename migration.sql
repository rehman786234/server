-- 1) videos table: uploader + creator fields
ALTER TABLE videos
  ADD COLUMN IF NOT EXISTS user_id     INT REFERENCES mydata(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '',
  ADD COLUMN IF NOT EXISTS visibility  VARCHAR(10) NOT NULL DEFAULT 'public', -- public | unlisted | private
  ADD COLUMN IF NOT EXISTS video_type  VARCHAR(10) NOT NULL DEFAULT 'long',
  ADD COLUMN IF NOT EXISTS duration    INT DEFAULT 0,                          -- seconds
  ADD COLUMN IF NOT EXISTS file_size   BIGINT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS views       INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMP DEFAULT NOW();
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
