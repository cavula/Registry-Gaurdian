"""Inventory normalization using SDK-shaped mocks only."""

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

import pytest

from guardian.registries.acr import ACRReader, create_acr_reader
from guardian.registries.base import DockerHubReader, GHCRReader
from guardian.registries.fixtures import FixtureRegistry


def sdk() -> Mock:
    client = Mock()
    client.list_repository_names.return_value = iter(["b", "a"])
    client.list_manifest_properties.return_value = iter(
        [
            NS(
                digest="idx",
                tags=["old"],
                created_on=datetime(2020, 1, 1, tzinfo=UTC),
                size_in_bytes=10,
                can_delete=True,
            ),
            NS(digest="child", tags=[], created_on=None, size_in_bytes=4, can_delete=False),
        ]
    )
    client.list_tag_properties.return_value = iter(
        [
            NS(digest="idx", name="prod", can_delete=True),
            NS(digest="idx", name="old", can_delete=True),
        ]
    )
    client.get_manifest.side_effect = [
        NS(manifest={"schemaVersion": 2, "manifests": [{"digest": "child"}]}),
        NS(manifest={"schemaVersion": 2, "layers": [{"digest": "layer", "size": 99}]}),
    ]
    return client


def test_sdk_paging_tags_indexes_locks() -> None:
    client = sdk()
    reader = ACRReader("demo", client)
    assert reader.list_repositories() == ["a", "b"]
    images = reader.list_images("a")
    assert images[0].tags == ["old", "prod"]
    assert images[0].child_digests == ["child"]
    assert images[0].manifest_type == "index"
    assert images[1].locked
    assert not images[1].inventory_complete
    assert images[1].blobs == {"layer": 99, "child": 4}
    assert not hasattr(reader, "delete_image")
    client.delete_manifest.assert_not_called()


def test_partial_tags_and_children_fail_closed() -> None:
    client = sdk()
    client.list_tag_properties.side_effect = RuntimeError("unavailable")
    client.get_manifest.side_effect = [
        NS(manifest={"schemaVersion": 2, "manifests": [{"digest": "missing"}]}),
        RuntimeError("unavailable"),
    ]
    images = ACRReader("demo", client).list_images("a")
    assert all(not image.inventory_complete for image in images)
    assert all(not image.children_complete for image in images)


def test_inventory_listing_failure_is_not_empty_inventory() -> None:
    client = Mock()
    client.list_manifest_properties.side_effect = RuntimeError("pagination failed")
    with pytest.raises(RuntimeError):
        ACRReader("demo", client).list_images("a")


def test_factory_only_wires_mocks() -> None:
    with (
        patch("azure.containerregistry.ContainerRegistryClient") as client,
        patch("azure.identity.DefaultAzureCredential") as credential,
    ):
        reader = create_acr_reader("demo")
        assert isinstance(reader, ACRReader)
        client.assert_called_once_with(
            "https://demo.azurecr.io", credential=credential.return_value
        )


def test_fixture_and_future_stubs(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps({"images": [{"registry": "demo", "repository": "a", "digest": "x"}]})
    )
    reader = FixtureRegistry(path)
    assert reader.list_repositories() == ["a"]
    one = reader.list_images("a")[0]
    one.tags.append("changed")
    assert reader.list_images("a")[0].tags == []
    for stub in [DockerHubReader(), GHCRReader()]:
        with pytest.raises(NotImplementedError):
            stub.list_repositories()
        with pytest.raises(NotImplementedError):
            stub.list_images("a")
