package adapter

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/h2hsecure/sshkeyman/internal/domain"
	bolt "go.etcd.io/bbolt"
)

const (
	bucketSSH = "ssh_keys"
)

func NewBoldDB(path string, readOnly bool) (domain.BoltDB, error) {
	db, err := bolt.Open(path, 0o644, &bolt.Options{Timeout: 10, ReadOnly: readOnly})
	if err != nil {
		return nil, fmt.Errorf("db open: path '%s' %w", path, err)
	}

	tx, err := db.Begin(true)
	if err != nil {
		return nil, fmt.Errorf("db view: %w", err)
	}

	_, err = tx.CreateBucketIfNotExists([]byte(bucketSSH))
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("create bucket: %w", err)
	}

	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &boltAdapter{db: db}, nil
}

type boltAdapter struct {
	db *bolt.DB
}

func (b *boltAdapter) Close() error {
	return b.db.Close()
}

// CreateUser implements BoltDB.
func (b *boltAdapter) CreateUser(ctx context.Context, username string, keyDto domain.KeyDto) error {
	tx, err := b.db.Begin(true)
	if err != nil {
		return fmt.Errorf("db view: %w", err)
	}
	m, err := json.Marshal(keyDto)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("db value marshal: %w", err)
	}

	bucket := tx.Bucket([]byte(bucketSSH))

	err = bucket.Put([]byte(username), m)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("db put: %w", err)
	}

	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("db view: %w", err)
	}

	return nil
}

// ReadUser implements BoltDB.
func (b *boltAdapter) ReadUser(ctx context.Context, username string) (domain.KeyDto, error) {
	var sshKeysForUsers []byte

	tx, err := b.db.Begin(false)
	if err != nil {
		return domain.KeyDto{}, fmt.Errorf("db begin: %w", err)
	}

	bucket := tx.Bucket([]byte(bucketSSH))

	if bucket == nil {
		return domain.KeyDto{}, fmt.Errorf("db bucket not found: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	sshKeysForUsers = bucket.Get([]byte(username))

	if sshKeysForUsers == nil {
		return domain.KeyDto{}, fmt.Errorf("user not found: %s: %w", username, domain.ErrNotFound)
	}

	var keyDto domain.KeyDto

	err = json.Unmarshal(sshKeysForUsers, &keyDto)
	if err != nil {
		return domain.KeyDto{}, fmt.Errorf("db value unmarshal: %w", err)
	}

	return keyDto, nil
}

func (b *boltAdapter) ReadUserById(ctx context.Context, uid uint) (domain.KeyDto, error) {
	tx, err := b.db.Begin(false)
	if err != nil {
		return domain.KeyDto{}, fmt.Errorf("db begin: %w", err)
	}

	bucket := tx.Bucket([]byte(bucketSSH))

	defer func() {
		_ = tx.Rollback()
	}()

	if bucket == nil {
		return domain.KeyDto{}, fmt.Errorf("db bucket not found: %w", err)
	}

	var retKeyDto domain.KeyDto

	err = bucket.ForEach(func(k, v []byte) error {
		var keyDto domain.KeyDto

		err = json.Unmarshal(v, &keyDto)
		if err != nil {
			return fmt.Errorf("db value unmarshal: %w", err)
		}
		if keyDto.User.UID == uid {
			retKeyDto = keyDto
		}

		return nil
	})
	if err != nil {
		return retKeyDto, fmt.Errorf("db foreach: %w", err)
	}

	return retKeyDto, err
}
