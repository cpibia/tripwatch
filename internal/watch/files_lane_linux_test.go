package watch

import "testing"

// Root's events take a lane of their own: a full channel of other accounts' events does not
// lose them, and losing one of them is counted as root's.
func TestFilesRootLane(t *testing.T) {
	out, urgent := make(chan Event, 1), make(chan Event, 1)
	b := &Batcher{}
	b.SetHomes([]Home{{User: "alice", Dir: "/home/alice", UID: 1000}})
	f := &Files{out: out, Urgent: urgent, IsRootEvent: b.RootEvent}
	f.send(Event{Class: ClassSSH, Op: OpCreate, Path: "/home/alice/.ssh", Dir: true})
	f.send(Event{Class: ClassSSH, Op: OpDelete, Path: "/home/alice/.ssh", Dir: true})
	f.send(Event{Class: ClassSSH, Op: OpWrite, Path: "/root/.ssh/authorized_keys"})
	if f.Dropped.Load() != 1 || f.DroppedSystem.Load() != 0 || len(urgent) != 1 {
		t.Fatalf("dropped %d (%d root's), urgent %d", f.Dropped.Load(), f.DroppedSystem.Load(), len(urgent))
	}
	f.send(Event{Class: ClassPrivilege, Op: OpWrite, Path: "/etc/sudoers"})
	if f.DroppedSystem.Load() != 1 {
		t.Fatal("a lost root event is not counted as root's")
	}
}
