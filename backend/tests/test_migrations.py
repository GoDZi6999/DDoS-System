from alembic import command


def test_models_match_the_migrations(alembic_cfg):
    command.check(alembic_cfg)  # raises if the models and migrations drift apart


def test_downgrade_and_upgrade_round_trip(alembic_cfg):
    command.downgrade(alembic_cfg, "base")
    command.upgrade(alembic_cfg, "head")
