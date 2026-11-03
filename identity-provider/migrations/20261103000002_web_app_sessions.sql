-- Each web app's own session under the browser session it signed in through
-- (identity-provider/specs/auth.md § 1, "Sessions"): the tokens and the device a browser session
-- held until now are its web apps'. Those browser sessions end, and each browser signs in again
-- with its password; the desktop app's sessions stay.
UPDATE sessions SET revoked_at = now(), revoked_reason = 'sign_out'
    WHERE kind = 'browser' AND revoked_at IS NULL;
UPDATE sessions SET device_id = NULL WHERE kind = 'browser';

ALTER TABLE sessions
    -- A web app's: the browser session it hangs under, and ends with.
    ADD COLUMN browser_session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    DROP CONSTRAINT sessions_kind_check,
    ADD CONSTRAINT sessions_kind_check CHECK (kind IN ('browser', 'web', 'app')),
    DROP CONSTRAINT sessions_app_client,
    ADD CONSTRAINT sessions_client CHECK ((kind = 'browser') = (client_id IS NULL)),
    ADD CONSTRAINT sessions_web_browser CHECK ((kind = 'web') = (browser_session_id IS NOT NULL)),
    ADD CONSTRAINT sessions_browser_no_device CHECK (kind <> 'browser' OR device_id IS NULL);

-- One live session a browser session and client: its next sign-in there reuses it.
CREATE UNIQUE INDEX sessions_one_per_browser_and_client
    ON sessions (browser_session_id, client_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_browser_session_id
    ON sessions (browser_session_id) WHERE browser_session_id IS NOT NULL;
