# Docker fixtures for nfsdiag

This folder has Dockerfiles used to create bad NFS situations on purpose.

The idea is to test if `nfsdiag` can see the problem and print the expected warning or failure. It is useful while developing the tool, because NFS has many boring edge cases and it is easy to break one diagnostic when changing another.

Most of these containers are not production NFS servers. They are only test fixtures.

---

## Important about Docker and NFS

Some fixtures use the kernel NFS server inside the container. For this you normally need:

```sh
--privileged
```

And your host kernel must allow NFS server features from Docker.

If the host does not allow it, some fixtures will exit early. The automated test runner treats this as `SKIP`, not as a project failure.

This is normal, mainly on Docker Desktop, WSL, restricted CI runners, or machines without proper NFS kernel support.

---

## Build fixtures

From the project root:

```sh
make docker-list
```

Build all fixture images:

```sh
make docker-build-all
```

Build one fixture:

```sh
make docker-build-read-only-export
```

The image tag format is:

```text
nfsdiag-fixture:<fixture-name>
```

Example:

```text
nfsdiag-fixture:read-only-export
```

---

## Run automated tests

Run all fixture tests:

```sh
make test-fixtures
```

List tests:

```sh
make test-fixtures-list
```

Run only one:

```sh
make test-fixture-rpcbind-unreachable
```

The test script does this flow:

1. build the fixture image
2. run the container
3. get the Docker bridge IP
4. run `nfsdiag` against this IP
5. check if the expected output appears
6. stop/remove the container

For tests that need real mount, run as root:

```sh
sudo make test-fixtures
```

If the machine cannot run the NFS server fixture, the test is skipped.

---

## Run one fixture manually

Example with read-only export:

```sh
docker run --rm -d --name nfs-fixture --privileged nfsdiag-fixture:read-only-export
```

Get the container IP:

```sh
docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nfs-fixture
```

Run the tool:

```sh
sudo ./nfsdiag client --export /export <container-ip>
```

Stop the container:

```sh
docker stop nfs-fixture
```

---

## Fixtures available

### `Dockerfile.rpcbind-unreachable`

No rpcbind and no NFS service. This should make TCP/111 and TCP/2049 fail.

### `Dockerfile.nfs-port-unreachable`

rpcbind is running, but NFS TCP/2049 is not. Good to test network check separation.

### `Dockerfile.rpc-map-missing-nfs`

rpcbind answers, but there is no real NFS service registered.

### `Dockerfile.mountd-unavailable`

TCP/2049 accepts connection with a dummy listener, but there is no valid NFS/mountd RPC service.

### `Dockerfile.empty-exports`

NFS stack starts with no useful exports.

### `Dockerfile.mount-denied`

The export exists, but the client should be denied by export policy.

### `Dockerfile.permission-denied`

The export can exist, but access to the directory should fail because of permissions and squashing.

### `Dockerfile.acl-unsupported`

Tries to make ACL probing show unsupported/hidden ACL xattrs. This depends on host/kernel behavior.

### `Dockerfile.identity-denied`

Root can access, but non-root simulated identities should fail.

### `Dockerfile.read-only-export`

The export is read-only. Create/write tests should fail.

### `Dockerfile.root-squash`

Root is squashed to uid/gid `65534`. The tool should detect that a file created by root is not owned by uid `0`.

### `Dockerfile.locking-missing`

`statd` is not started. The tool should warn about NSM/statd for NFSv3 lock recovery.

### `Dockerfile.stale-handle`

The exported path is recreated in a loop to try to trigger `ESTALE`. This one is best effort, because stale handles depend on timing.

### `Dockerfile.slow-performance`

Applies `tc netem` delay/rate limit when the container has permission. Used to make performance numbers bad on purpose.

---

## Common helper files

The `common/` folder has shared files used by the fixtures:

- `kernel-nfs-entrypoint.sh`
- `rpcbind-only-entrypoint.sh`
- `tcp-listener.py`
- `exports.*`

The kernel NFS entrypoint mounts `/export` as `tmpfs` by default because Docker overlay filesystems normally cannot be exported by kernel NFS.

---

## Notes

Some fixtures intentionally trigger more than one warning or failure. This is fine. In real NFS problems, one bad thing usually causes many other checks to fail too.

For example, if NFS is not listening on TCP/2049, then mount tests will also fail. The important thing is that the first useful diagnostic points to the right direction.
