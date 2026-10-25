package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/valyala/fastjson"
)

// archiveEntry represents a file inside an archive. Its contents are streamed
// from 7-Zip; the decompressed file is never written to disk.
type archiveEntry struct {
	archivePath string
	entryPath   string
	name        string
	size        int64
	password    string
	sevenZip    string
}

func find7Zip() (string, error) {
	for _, name := range []string{"7z", "7zz", "7za", "7z.exe", "7zz.exe", "7za.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("找不到 7-Zip 命令（7z/7zz/7za），请安装 7-Zip 并将其加入 PATH")
}

// listArchive uses 7-Zip's machine-readable -slt output. Split-volume archives
// are handled by 7-Zip as long as the first volume and all other volumes exist.
func listArchive(archivePath, password, sevenZip string) ([]archiveEntry, error) {
	args := []string{"l", "-slt", "-sccUTF-8"}
	if password != "" {
		args = append(args, "-p"+password)
	}
	args = append(args, "--", archivePath)
	cmd := exec.Command(sevenZip, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("列出压缩包 %q 失败：%w：%s", archivePath, err, strings.TrimSpace(stderr.String()))
	}

	var entries []archiveEntry
	scanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	inEntries := false
	fields := map[string]string{}
	flush := func() {
		if !inEntries || fields["Path"] == "" || fields["Path"] == archivePath {
			fields = map[string]string{}
			return
		}
		entryPath := fields["Path"]
		if strings.HasSuffix(fields["Attributes"], "D") || fields["Folder"] == "+" || fields["Size"] == "" {
			fields = map[string]string{}
			return
		}
		size, err := strconv.ParseInt(fields["Size"], 10, 64)
		if err == nil && size >= 0 {
			normalized := strings.ReplaceAll(entryPath, "\\", "/")
			entries = append(entries, archiveEntry{
				archivePath: archivePath,
				entryPath:   entryPath,
				name:        path.Base(normalized),
				size:        size,
				password:    password,
				sevenZip:    sevenZip,
			})
		}
		fields = map[string]string{}
	}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "----------") {
			inEntries = true
			fields = map[string]string{}
			continue
		}
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if i := strings.Index(line, " = "); i >= 0 {
			fields[line[:i]] = line[i+3:]
		}
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 7-Zip 列表失败：%w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("压缩包 %q 中没有找到普通文件（或压缩包格式不受 7-Zip 支持）", archivePath)
	}
	return entries, nil
}

// ensureArchiveParentDir 创建或复用压缩包内文件所需的目录。
// archiveDirs 用于缓存已经解析过的内部目录，避免重复请求 115。
func ensureArchiveParentDir(
	entryPath string,
	rootCID uint64,
	archiveDirs map[string]uint64,
) (uint64, error) {
	entryPath = strings.ReplaceAll(entryPath, "\\", "/")
	entryPath = path.Clean(entryPath)

	// 防止绝对路径和路径穿越。
	if entryPath == "." ||
		path.IsAbs(entryPath) ||
		entryPath == ".." ||
		strings.HasPrefix(entryPath, "../") {
		return 0, fmt.Errorf("压缩包内部路径无效：%q", entryPath)
	}

	dir := path.Dir(entryPath)
	if dir == "." {
		return rootCID, nil
	}

	// 缓存以目标根目录 CID 和内部路径共同标识。
	key := strconv.FormatUint(rootCID, 10) + "/" + dir
	if cid, ok := archiveDirs[key]; ok {
		return cid, nil
	}

	parentCID := rootCID
	currentPath := ""

	for _, part := range strings.Split(dir, "/") {
		if part == "" || part == "." || part == ".." {
			return 0, fmt.Errorf("压缩包内部目录无效：%q", dir)
		}

		if currentPath == "" {
			currentPath = part
		} else {
			currentPath += "/" + part
		}

		key := strconv.FormatUint(rootCID, 10) + "/" + currentPath

		if cid, ok := archiveDirs[key]; ok {
			parentCID = cid
			continue
		}

		cid, err := createDir(parentCID, part)
		if err != nil {
			return 0, fmt.Errorf(
				"创建压缩包内部目录 %q 失败：%w",
				currentPath, err,
			)
		}

		archiveDirs[key] = cid
		parentCID = cid
	}

	return parentCID, nil
}

// stream starts 7-Zip for one entry and gives the decompressed bytes to consume.
// The callback must read until EOF; the process exit status is checked afterward.
func (entry *archiveEntry) stream(consume func(io.Reader) error) error {
	args := []string{"x", "-so", "-y", "-sccUTF-8"}
	if entry.password != "" {
		args = append(args, "-p"+entry.password)
	}
	args = append(args, entry.archivePath, entry.entryPath)
	cmd := exec.Command(entry.sevenZip, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 7-Zip 失败：%w", err)
	}
	consumeErr := consume(stdout)
	// Drain stdout to avoid blocking the child if the callback stops early.
	_, drainErr := io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if consumeErr != nil {
		return consumeErr
	}
	if drainErr != nil {
		return drainErr
	}
	if waitErr != nil {
		return fmt.Errorf("解压压缩包内文件 %q 失败：%w：%s", entry.entryPath, waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (entry *archiveEntry) hashSHA1() (blockHash, totalHash string, err error) {
	err = entry.stream(func(r io.Reader) error {
		first := make([]byte, 128*1024)
		n, readErr := io.ReadFull(r, first)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return readErr
		}
		block := sha1.Sum(first[:n])
		blockHash = strings.ToUpper(hex.EncodeToString(block[:]))
		h := sha1.New()
		_, _ = h.Write(first[:n])
		if _, copyErr := io.Copy(h, r); copyErr != nil {
			return copyErr
		}
		totalHash = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		return nil
	})
	return
}

func (entry *archiveEntry) hashRange(signCheck string) (string, error) {
	var start, end int64
	if _, err := fmt.Sscanf(signCheck, "%d-%d", &start, &end); err != nil {
		return "", fmt.Errorf("sign_check 范围错误：%s", signCheck)
	}
	if start < 0 || end < start || end >= entry.size {
		return "", fmt.Errorf("sign_check 范围超出文件大小：%s（文件大小 %d）", signCheck, entry.size)
	}
	h := sha1.New()
	err := entry.stream(func(r io.Reader) error {
		if _, err := io.CopyN(io.Discard, r, start); err != nil {
			return err
		}
		_, err := io.CopyN(h, r, end-start+1)
		return err
	})
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), nil
}

// uploadArchiveFileSHA1 follows the same 115 instant-upload handshake as a
// regular file, reopening the archive stream only when 115 asks for sign_check.
func (file *fileInfo) uploadArchiveFileSHA1() (body []byte, fileSHA1 string, err error) {
	entry := file.Archive
	_, fileSHA1, err = entry.hashSHA1()
	if err != nil {
		return nil, "", err
	}
	fileSize := strconv.FormatInt(entry.size, 10)
	body, err = uploadSHA1(entry.name, fileSize, fileSHA1, "", "", file.ParentID)
	if err != nil {
		return nil, "", err
	}
	var parser fastjson.Parser
	v, err := parser.ParseBytes(body)
	if err != nil {
		return nil, "", err
	}
	if v.GetInt("status") == 7 && v.GetInt("statuscode") == 701 {
		signKey := string(v.GetStringBytes("sign_key"))
		signCheck := string(v.GetStringBytes("sign_check"))
		signVal, err := entry.hashRange(signCheck)
		if err != nil {
			return nil, "", err
		}
		body, err = uploadSHA1(entry.name, fileSize, fileSHA1, signKey, signVal, file.ParentID)
		if err != nil {
			return nil, "", err
		}
	}
	return body, fileSHA1, nil
}
