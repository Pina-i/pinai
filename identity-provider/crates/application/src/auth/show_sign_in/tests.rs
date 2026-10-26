use domain::auth::testing::{a_request, signed_up};
use domain::auth::{
    AuthorizationRequest, ClientId, INVITATION_TTL, LOGIN_TICKET_TTL, SignInAccount,
};

use crate::auth::world::{now, world};

use super::*;

#[tokio::test]
async fn a_page_is_shown_for_a_request_its_client_may_be_sent_back_to() {
    let w = world().await;
    let stranger = AuthorizationRequest {
        client: ClientId::parse("http://localhost:5173/stranger.json").unwrap(),
        ..a_request()
    };
    let elsewhere = AuthorizationRequest {
        redirect_uri: "https://evil.test/callback".to_owned(),
        ..a_request()
    };

    let fine = w.show.request(&a_request()).await;
    let unknown = w.show.request(&stranger).await;
    let unregistered = w.show.request(&elsewhere).await;

    assert_eq!(fine.unwrap().id, a_request().client);
    assert!(
        matches!(unknown, Err(AuthError::UnknownClient)),
        "{unknown:?}"
    );
    assert!(
        matches!(unregistered, Err(AuthError::UnregisteredRedirect)),
        "{unregistered:?}"
    );
}

#[tokio::test]
async fn a_second_factor_page_is_shown_for_an_open_ticket_only() {
    let w = world().await;
    let bob = signed_up("bob");
    let ticket = w
        .tickets
        .open(bob.id, &a_request(), now() + LOGIN_TICKET_TTL)
        .await
        .unwrap();

    assert_eq!(
        w.show.ticket(ticket, now()).await.unwrap(),
        Some(a_request())
    );
    assert_eq!(
        w.show
            .ticket(ticket, now() + LOGIN_TICKET_TTL)
            .await
            .unwrap(),
        None,
        "expired"
    );
    assert_eq!(
        w.show.ticket(TicketId::generate(), now()).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn an_invitation_page_is_shown_for_an_open_invitation_only() {
    let w = world().await;
    let admin = SignInAccount {
        admin: true,
        display_name: Some("Kahu".to_owned()),
        ..signed_up("kahu")
    };
    w.sign_up(&admin).await;
    let expires_at = now() + INVITATION_TTL;
    let (id, token) = w.accounts.issue(admin.id, now(), expires_at).await.unwrap();

    let open = w.show.invitation(&token, now()).await.unwrap();
    let expired = w.show.invitation(&token, expires_at).await.unwrap();
    let unknown = w
        .show
        .invitation(&InvitationToken::from_bytes([1; 32]), now())
        .await
        .unwrap();

    assert_eq!(
        open,
        Some(OpenInvitation {
            id,
            inviter: Some("Kahu".to_owned()),
            created_at: now(),
            expires_at,
        })
    );
    assert_eq!((expired, unknown), (None, None));
}
