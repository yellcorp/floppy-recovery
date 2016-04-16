from msfat.chkdsk.log import _PrefixLogger


_MAX_VALID =    0x0FFFFFF6

# means the chain is terminated by a bad cluster
_BAD_CLUSTER =  0x0FFFFFF7

# normal end
_NORMAL_END =   0x0FFFFFF8

# cluster is free
_FREE =         0x0FFFFFFA

# on-disk link is out of range
_INVALID =      0x0FFFFFF9

# anonymous chain linked to named chain and was thus broken
_NAMED =        0x0FFFFFFA


def _plural(n, singular, plural, format_spec=""):
    return "{0} {1}".format(format(n, format_spec), n == 1 and singular or plural)


def _status_string(n):
    if n == _BAD_CLUSTER:
        return "bad cluster"
    if n == _NORMAL_END:
        return "normal end-of-chain marker"
    if n == _FREE:
        return "free cluster"
    if n == _INVALID:
        return "invalid cluster number"
    if n == _NAMED:
        return "named chain"
    return "normal link"


class _Node(object):
    def __init__(self, index, value):
        self.index = index
        self.prevs = set()
        self.next_node = 0
        self.value = value
        self.label = 0
        self.named = False

    def has_next(self):
        return self.next_node <= _MAX_VALID


class _AllocChecker(object):
    def __init__(self, volume, log):
        self.volume = volume
        self.log = log
        self._node_count = self.volume._max_cluster_num + 1
        self._nodes = None
        self._named_starts = [ ]
        self._index_to_name = [ "<FREE>", "<INVALID>" ]
        self._name_to_index = dict((n, i) for i, n in enumerate(self._index_to_name))

        self._free_count = 0
        self._bad_count = 0
        self._invalid_count = 0
        self._truncated_count = 0
        self._anonymous_count = 0

        self._anon_name_counter = 1

        self._load_fat()

    def _load_fat(self):
        nodes = [ None, None ]
        for cluster_num in range(2, self._node_count):
            value = self.volume._get_fat_entry(cluster_num)
            nodes.append(_Node(cluster_num, value))

        for cluster_num in range(2, self._node_count):
            node = nodes[cluster_num]

            if node.value == 0:
                node.next_node = _FREE
                self._free_count += 1

            elif self.volume._is_bad(node.value):
                node.next_node = _BAD_CLUSTER
                self._bad_count += 1

            elif self.volume._is_eoc(node.value):
                node.next_node = _NORMAL_END

            elif not self.volume._is_valid_cluster_num(node.value):
                node.next_node = _INVALID
                self._invalid_count += 1

            else:
                node.next_node = node.value
                nodes[node.next_node].prevs.add(node.next_node)

        self._nodes = nodes

    def mark_chain(self, start_cluster, name=None, expect_bytes=0):
        has_name = name is not None

        if not has_name:
            name = "<Anonymous #{0} @{1:#010x}>".format(self._anon_name_counter, start_cluster)
            self._anon_name_counter += 1

        log = _PrefixLogger(self.log.log, name + " ")
        log_func = has_name and log.invalid or log.info

        expect_cluster_count = (expect_bytes + self.volume._bytes_per_cluster - 1) / self.volume._bytes_per_cluster
        actual_cluster_count = 0

        def cluster_count_string():
            return _plural(actual_cluster_count, "cluster", "clusters")

        label = self._add_name(name)

        self._named_starts.append(start_cluster)

        prev_cluster = 0
        cluster = start_cluster

        while cluster <= _MAX_VALID:
            node = self._nodes[cluster]

            if node.named:
                log_func("""is cross-linked with {other}
                    at cluster {cluster_num:#010x}
                    after {cluster_count}""",
                    other=self._index_to_name[node.label],
                    cluster_num=node.index,
                    cluster_count=cluster_count_string()
                )
                break

            else:
                node.named = True
                node.label = label

            prev_cluster = cluster
            cluster = node.next_node
            actual_cluster_count += 1

        if cluster > _MAX_VALID and cluster != _NORMAL_END:
            log_func("""links to {desc} ({value:#010x})
                from {prev:#010x}
                after {cluster_count}""",
                desc=_status_string(cluster),
                value=node.value,
                prev=prev_cluster,
                cluster_count=cluster_count_string()
            )
            self._truncated_count += 1

        if expect_cluster_count > 0 and expect_cluster_count != actual_cluster_count:
            log.invalid("""is too {adjective}. Expected cluster count of
                {expect} for {expect_bytes:#x} bytes, found {got}""",
                adjective=actual_cluster_count > expect_cluster_count and "long" or "short",
                expect=expect_cluster_count,
                expect_bytes=expect_bytes,
                got=actual_cluster_count
            )

        return actual_cluster_count


    def finalize_marked(self):
        for node_index in self._named_starts:
            node = self._nodes[node_index]
            for incoming_index in node.prevs:
                incoming_node = self._nodes[incoming_index]
                # break an anonymous chain if it leads into a named one
                if incoming_node.label == 0:
                    incoming_node.next_node = _NAMED
                    node.prevs.remove(incoming_index)

        for index in range(2, self._node_count):
            node = self._nodes[index]
            if not node.named and node.next_node not in (_BAD_CLUSTER, _FREE, _INVALID):
                self._anonymous_count += 1


    def find_anonymous_chains(self):
        seen = bytearray(self._node_count)

        for index in range(2, self._node_count):
            # if we've seen it, skip it
            if seen[index]:
                continue

            node = self._nodes[index]
            # if it belongs to a named file, or it's free/bad with no incoming
            # links, skip it
            if node.named or (node.next_node in (_BAD_CLUSTER, _FREE) and not node.prevs):
                continue

            # list of nodes we are tracing backwards to find heads
            currents = [ node ]
            while currents:
                nexts = [ ]
                for n in currents:
                    # check again we haven't seen it - avoid cycles
                    if not seen[n.index]:
                        seen[n.index] = 1  # mark it off

                        # no incoming links? we've found a head.
                        if not n.prevs:
                            yield n.index

                        # otherwise all incoming links go in the next iteration
                        else:
                            nexts.extend(self._nodes[pindex] for pindex in n.prevs)

                # iterate
                currents = nexts


    def _add_name(self, name):
        if name in self._name_to_index:
            raise ValueError("Name {0!r} already exists")

        new_index = len(self._index_to_name)
        self._name_to_index[name] = new_index
        self._index_to_name.append(name)
        return new_index
