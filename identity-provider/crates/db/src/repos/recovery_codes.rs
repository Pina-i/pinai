use sqlx::PgPool;
use uuid::Uuid;

use crate::models::RecoveryCode;

/// Atomic regenerate: invalidate all existing codes for a user, then insert
/// the fresh batch in the same transaction. Returns the new rows.
pub async fn replace_all(
    pool: &PgPool,
    user_id: Uuid,
    new_hashes: &[Vec<u8>],
) -> Result<Vec<RecoveryCode>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    let mut out = Vec::with_capacity(new_hashes.len());
    for hash in new_hashes {
        let row = sqlx::query_as::<_, RecoveryCode>(
            r#"
            INSERT INTO recovery_codes (user_id, code_hash)
            VALUES ($1, $2)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(hash)
        .fetch_one(&mut *tx)
        .await?;
        out.push(row);
    }

    tx.commit().await?;
    Ok(out)
}

pub async fn list_unconsumed(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<RecoveryCode>, sqlx::Error> {
    sqlx::query_as::<_, RecoveryCode>(
        r#"
        SELECT *
          FROM recovery_codes
         WHERE user_id = $1 AND consumed_at IS NULL
         ORDER BY created_at
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

pub async fn count_unconsumed(pool: &PgPool, user_id: Uuid) -> Result<i64, sqlx::Error> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT FROM recovery_codes WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// Atomic single-use consumption — returns `true` only if the row was
/// actually flipped (defends against the race where two concurrent attempts
/// could each burn the same code).
pub async fn consume(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        r#"
        UPDATE recovery_codes
           SET consumed_at = now()
         WHERE id = $1 AND consumed_at IS NULL
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn delete_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}
