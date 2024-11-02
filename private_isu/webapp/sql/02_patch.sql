CREATE INDEX idx_post_id_created_at ON `comments` (`post_id`, `created_at`);
CREATE INDEX idx_user_id ON `comments` (`user_id`);
CREATE INDEX idx_created_at ON `posts` (`created_at`);
