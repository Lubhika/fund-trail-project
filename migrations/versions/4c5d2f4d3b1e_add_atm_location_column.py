"""Add atm_location column to transaction table if missing.

Revision ID: 4c5d2f4d3b1e
Revises: 639e2a9d0ff7
Create Date: 2025-12-15 12:55:00
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "4c5d2f4d3b1e"
down_revision = "639e2a9d0ff7"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("transaction")}

    if "atm_location" not in columns:
        with op.batch_alter_table("transaction") as batch_op:
            batch_op.add_column(sa.Column("atm_location", sa.String(length=200), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("transaction")}

    if "atm_location" in columns:
        with op.batch_alter_table("transaction") as batch_op:
            batch_op.drop_column("atm_location")

