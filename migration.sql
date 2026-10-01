-- 1) videos table: uploader + creator fields
ALTER TABLE videos
  ADD COLUMN IF NOT EXISTS user_id     INT REFERENCES mydata(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '',
  ADD COLUMN IF NOT EXISTS visibility  VARCHAR(10) NOT NULL DEFAULT 'public', -- public | unlisted | private
  ADD COLUMN IF NOT EXISTS duration    INT DEFAULT 0,                          -- seconds
  ADD COLUMN IF NOT EXISTS file_size   BIGINT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS views       INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMP DEFAULT NOW();
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
