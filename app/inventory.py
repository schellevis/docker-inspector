"""Docker socket integration — list running images."""

import logging

import docker

logger = logging.getLogger(__name__)


def get_running_images() -> list[dict]:
    """
    Connect to the Docker socket and return a deduplicated list of images
    currently in use by running containers.

    Each entry: {"image_id": str, "tags": list[str]}
    """
    try:
        client = docker.from_env()
    except Exception as exc:
        logger.error("Cannot connect to Docker socket: %s", exc)
        return []

    seen: dict[str, list[str]] = {}  # image_id -> tags
    try:
        containers = client.containers.list()
    except Exception as exc:
        logger.error("Cannot list containers: %s", exc)
        return []

    for container in containers:
        try:
            image = container.image
            image_id: str = image.id  # full sha256:...
            tags: list[str] = image.tags or []
            if image_id in seen:
                # Merge tags (deduplicate)
                merged = list(dict.fromkeys(seen[image_id] + tags))
                seen[image_id] = merged
            else:
                seen[image_id] = tags
        except Exception as exc:
            logger.warning(
                "Skipping container %s due to error: %s", container.id[:12], exc
            )

    result = [{"image_id": iid, "tags": tags} for iid, tags in seen.items()]
    logger.info("Found %d unique image(s) from running containers", len(result))
    return result
