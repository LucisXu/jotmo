package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	jwtSecret              = []byte("jotmo-secret-key-medieval-2024")
	dataFile               = "jotmo_data.json"
	dataMutex              sync.RWMutex
	dashscopeAPIKey        = os.Getenv("DASHSCOPE_API_KEY")
	skipNameGen            = false // 跳过分类名称生成（用于离线重聚类）
	activeCorridorProcess  = make(map[int]bool) // 跟踪活跃的时光回廊处理任务
	pausedCorridorProcess  = make(map[int]bool) // 跟踪暂停的时光回廊处理任务
	corridorProcessMutex   sync.RWMutex
)

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// ============ 数据结构 ============

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Note struct {
	ID          int       `json:"id"`
	UserID      int       `json:"user_id"`
	Content     string    `json:"content"`
	CreatedAt   string    `json:"created_at"`
	Embedding   []float32 `json:"embedding,omitempty"`
	CategoryID  int       `json:"category_id"`
	ThemeID     int       `json:"theme_id"`      // 用户自定义主题
	CatResponse string    `json:"cat_response"`  // 猫咪回复
}

// Theme 用户自定义的主题（手动整理）
type Theme struct {
	ID        int    `json:"id"`
	UserID    int    `json:"user_id"`
	Name      string `json:"name"`
	Color     string `json:"color"`     // 主题颜色
	CreatedAt string `json:"created_at"`
}

type Category struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Name      string    `json:"name"`
	ParentID  int       `json:"parent_id"` // 0 表示一级分类
	Centroid  []float32 `json:"centroid"`
	NoteCount int       `json:"note_count"`
	CreatedAt string    `json:"created_at"`
}

type Data struct {
	Users          []User     `json:"users"`
	Notes          []Note     `json:"notes"`
	Categories     []Category `json:"categories"`
	Themes         []Theme    `json:"themes"`
	NextUserID     int        `json:"next_user_id"`
	NextNoteID     int        `json:"next_note_id"`
	NextCategoryID int        `json:"next_category_id"`
	NextThemeID    int        `json:"next_theme_id"`
	// 持久化缓存
	UserInsights   map[int]*InsightReport   `json:"user_insights,omitempty"`
	UserStarlight  map[int]*StarlightCache  `json:"user_starlight,omitempty"`
	UserBiography  map[int]*BiographyReport `json:"user_biography,omitempty"`
	// 时光回廊 - 快记图片
	NoteImages     map[int]*NoteImage       `json:"note_images,omitempty"`
	// 时光回廊批量处理状态
	CorridorStatus map[int]*CorridorProcessStatus `json:"corridor_status,omitempty"`
}

// NoteImage 快记生成的场景图片
type NoteImage struct {
	NoteID        int    `json:"note_id"`
	ImageURL      string `json:"image_url"`       // 图片 URL（DashScope 临时链接或本地存储路径）
	LocalPath     string `json:"local_path"`      // 本地存储路径
	ThumbnailPath string `json:"thumbnail_path"`  // 缩略图路径
	Prompt        string `json:"prompt"`          // 生成使用的 prompt
	Status        string `json:"status"`          // pending, generating, completed, failed, not_suitable
	TaskID        string `json:"task_id"`         // DashScope 任务 ID
	GeneratedAt   string `json:"generated_at"`    // 生成时间
	Error         string `json:"error"`           // 错误信息
}

// CorridorProcessStatus 时光回廊批量处理状态
type CorridorProcessStatus struct {
	Status           string `json:"status"`            // idle, processing, paused, completed, interrupted, error
	TotalNotes       int    `json:"total_notes"`       // 总快记数
	ProcessedNotes   int    `json:"processed_notes"`   // 已处理数
	SuccessCount     int    `json:"success_count"`     // 成功生成数
	FailedCount      int    `json:"failed_count"`      // 失败数
	NotSuitableCount int    `json:"not_suitable_count"` // 不适合生成图片的数量
	LastProcessedAt  string `json:"last_processed_at"` // 最后处理时间
	StartedAt        string `json:"started_at"`        // 开始时间
	Error            string `json:"error"`             // 错误信息
}

// StarlightCache Starlight 报告缓存
type StarlightCache struct {
	Report      string `json:"report"`
	GeneratedAt string `json:"generated_at"`
	NoteCount   int    `json:"note_count"`
}

// BiographyGenerationStatus 传记生成状态（内存中，不持久化）
type BiographyGenerationStatus struct {
	Status      string `json:"status"`       // idle, generating, completed, error
	Phase       string `json:"phase"`        // 当前阶段描述
	Progress    int    `json:"progress"`     // 进度百分比 0-100
	CurrentStep int    `json:"current_step"` // 当前步骤
	TotalSteps  int    `json:"total_steps"`  // 总步骤数
	StartedAt   string `json:"started_at"`   // 开始时间
	Error       string `json:"error"`        // 错误信息
}

// 全局生成状态 map（内存中）
var biographyGenStatus = make(map[int]*BiographyGenerationStatus)
var biographyGenMutex sync.RWMutex

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type NoteRequest struct {
	Content string `json:"content"`
}

type ImportNoteRequest struct {
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
}

type ImportRequest struct {
	Notes []ImportNoteRequest `json:"notes"`
}

// ============ 洞见模块数据结构 ============

type InsightReport struct {
	MBTI         MBTIAnalysis    `json:"mbti"`
	Emotions     EmotionAnalysis `json:"emotions"`
	Keywords     []Keyword       `json:"keywords"`
	Future       FutureForecast  `json:"future"`
	PersonalNote string          `json:"personal_note"`
	GeneratedAt  string          `json:"generated_at"`
	NoteCount    int             `json:"note_count"`
}

type MBTIAnalysis struct {
	Type        string      `json:"type"`        // e.g., "INFP"
	TypeName    string      `json:"type_name"`   // e.g., "调停者"
	TypeEmoji   string      `json:"type_emoji"`  // e.g., "🌸"
	Dimensions  []Dimension `json:"dimensions"`  // E/I, S/N, T/F, J/P scores
	Description string      `json:"description"` // 温暖的描述
	Traits      []string    `json:"traits"`      // 核心特质标签
	Evidences   []string    `json:"evidences"`   // 来自快记的证据
}

type Dimension struct {
	Name   string `json:"name"`   // e.g., "E-I"
	Left   string `json:"left"`   // e.g., "外向"
	Right  string `json:"right"`  // e.g., "内向"
	Score  int    `json:"score"`  // 0-100, 50为中间
	Lean   string `json:"lean"`   // "left" or "right"
}

type EmotionAnalysis struct {
	Dominant     string         `json:"dominant"`     // 主导情绪
	DomEmoji     string         `json:"dom_emoji"`    // 主导情绪emoji
	Distribution []EmotionItem  `json:"distribution"` // 情绪分布
	Trend        string         `json:"trend"`        // 情绪走势描述
	Insight      string         `json:"insight"`      // 情绪洞察
}

type EmotionItem struct {
	Name    string `json:"name"`
	Emoji   string `json:"emoji"`
	Count   int    `json:"count"`
	Percent int    `json:"percent"`
	Color   string `json:"color"` // 用于环形图
}

type Keyword struct {
	Word    string `json:"word"`
	Count   int    `json:"count"`
	Size    int    `json:"size"`    // 1-5, 用于词云大小
	Emotion string `json:"emotion"` // positive/neutral/reflective/concern
}

// 未来预见相关结构
type FutureForecast struct {
	EmergingInterests []InterestItem  `json:"emerging_interests"` // 兴趣萌芽
	GrowthTrajectory  TrajectoryItem  `json:"growth_trajectory"`  // 发展趋势
	HiddenPotential   []PotentialItem `json:"hidden_potential"`   // 潜力发现
	Summary           string          `json:"summary"`            // 整体展望
}

type InterestItem struct {
	Topic      string `json:"topic"`      // 兴趣主题
	Emoji      string `json:"emoji"`      // 代表emoji
	Signal     string `json:"signal"`     // 从哪些记录中发现的信号
	Suggestion string `json:"suggestion"` // 探索建议
}

type TrajectoryItem struct {
	FromState string `json:"from_state"` // 过去的状态
	ToState   string `json:"to_state"`   // 正在转向的状态
	Evidence  string `json:"evidence"`   // 支持这个判断的证据
	Meaning   string `json:"meaning"`    // 这意味着什么
}

type PotentialItem struct {
	Ability     string `json:"ability"`     // 潜在能力
	Emoji       string `json:"emoji"`       // 代表emoji
	Evidence    string `json:"evidence"`    // 从哪些记录中看出
	Affirmation string `json:"affirmation"` // 肯定的话语
}

// ============ 我的传奇 - 个人传记模块 ============

// BiographyReport 个人传记报告
type BiographyReport struct {
	// 封面
	Title      string `json:"title"`       // 传记标题
	Subtitle   string `json:"subtitle"`    // 副标题
	CoverEmoji string `json:"cover_emoji"` // 封面emoji

	// 人物画像
	Portrait Portrait `json:"portrait"`

	// 人生篇章
	Chapters []Chapter `json:"chapters"`

	// 人生主题
	LifeThemes []LifeTheme `json:"life_themes"`

	// 金句集
	Quotes []Quote `json:"quotes"`

	// 人生轨迹
	Timeline []TimelineEvent `json:"timeline"`

	// 尾声
	Epilogue string `json:"epilogue"`

	// 元数据（用于增量更新）
	GeneratedAt   string `json:"generated_at"`
	LastUpdatedAt string `json:"last_updated_at"`
	LastNoteID    int    `json:"last_note_id"` // 最后处理的快记ID
	NoteCount     int    `json:"note_count"`
	Version       int    `json:"version"`
}

// Portrait 人物画像
type Portrait struct {
	Tagline      string   `json:"tagline"`       // 一句话定义
	Essence      string   `json:"essence"`       // 核心特质描述
	Strengths    []string `json:"strengths"`     // 闪光点
	Quirks       []string `json:"quirks"`        // 独特之处
	DrivingForce string   `json:"driving_force"` // 内心驱动力
	Spirit       string   `json:"spirit"`        // 精神图腾
}

// Chapter 人生篇章
type Chapter struct {
	ID         int      `json:"id"`
	Title      string   `json:"title"`
	Subtitle   string   `json:"subtitle"`
	Emoji      string   `json:"emoji"`
	Period     string   `json:"period"`
	Opening    string   `json:"opening"`
	Narrative  string   `json:"narrative"`
	KeyMoments []string `json:"key_moments"`
	Emotions   []string `json:"emotions"`
	Growth     string   `json:"growth"`
	Closing    string   `json:"closing"`
}

// LifeTheme 人生主题
type LifeTheme struct {
	Theme          string   `json:"theme"`
	Emoji          string   `json:"emoji"`
	Description    string   `json:"description"`
	Manifestations []string `json:"manifestations"`
	Evolution      string   `json:"evolution"`
}

// Quote 金句
type Quote struct {
	Text    string `json:"text"`
	Source  string `json:"source"`
	Emoji   string `json:"emoji"`
	Meaning string `json:"meaning"`
}

// TimelineEvent 时间线事件
type TimelineEvent struct {
	Date         string `json:"date"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Emoji        string `json:"emoji"`
	Significance string `json:"significance"`
}

// BiographyUpdate 增量更新结构
type BiographyUpdate struct {
	UpdateType        string          `json:"update_type"` // none, minor, major
	PortraitUpdate    *PortraitUpdate `json:"portrait_update,omitempty"`
	ChapterUpdates    []ChapterUpdate `json:"chapter_updates,omitempty"`
	NewChapter        *Chapter        `json:"new_chapter,omitempty"`
	NewThemes         []LifeTheme     `json:"new_themes,omitempty"`
	ThemeUpdates      []ThemeUpdate   `json:"theme_updates,omitempty"`
	NewQuotes         []Quote         `json:"new_quotes,omitempty"`
	NewTimelineEvents []TimelineEvent `json:"new_timeline_events,omitempty"`
	EpilogueUpdate    string          `json:"epilogue_update,omitempty"`
	UpdateSummary     string          `json:"update_summary"`
}

type PortraitUpdate struct {
	EssenceAddition string   `json:"essence_addition,omitempty"`
	NewStrengths    []string `json:"new_strengths,omitempty"`
	NewQuirks       []string `json:"new_quirks,omitempty"`
}

type ChapterUpdate struct {
	ChapterID         int      `json:"chapter_id"`
	NarrativeAddition string   `json:"narrative_addition,omitempty"`
	NewKeyMoments     []string `json:"new_key_moments,omitempty"`
	GrowthUpdate      string   `json:"growth_update,omitempty"`
}

type ThemeUpdate struct {
	Theme              string   `json:"theme"`
	EvolutionUpdate    string   `json:"evolution_update,omitempty"`
	NewManifestations  []string `json:"new_manifestations,omitempty"`
}

// DashScope API 请求/响应
type DashScopeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type DashScopeInput struct {
	Messages []DashScopeMessage `json:"messages"`
}

type DashScopeParameters struct {
	MaxTokens   int     `json:"max_tokens,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
}

type DashScopeRequest struct {
	Model      string              `json:"model"`
	Input      DashScopeInput      `json:"input"`
	Parameters DashScopeParameters `json:"parameters,omitempty"`
}

type DashScopeChoice struct {
	Message DashScopeMessage `json:"message"`
}

type DashScopeOutput struct {
	Choices []DashScopeChoice `json:"choices"`
	Text    string            `json:"text,omitempty"`
}

type DashScopeResponse struct {
	Output DashScopeOutput `json:"output"`
}

var data Data

// ============ 数据加载/保存 ============

func loadData() {
	dataMutex.Lock()
	defer dataMutex.Unlock()

	file, err := os.ReadFile(dataFile)
	if err != nil {
		data = Data{
			Users:          []User{},
			Notes:          []Note{},
			Categories:     []Category{},
			NextUserID:     1,
			NextNoteID:     1,
			NextCategoryID: 1,
		}
		return
	}

	json.Unmarshal(file, &data)

	// 确保 Categories 不为 nil
	if data.Categories == nil {
		data.Categories = []Category{}
	}
	if data.NextCategoryID == 0 {
		data.NextCategoryID = 1
	}
}

func saveData() {
	file, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(dataFile, file, 0644)
}

// ============ CORS & Auth ============

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func generateToken(userID int, username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})
	return token.SignedString(jwtSecret)
}

func validateToken(tokenString string) (int, string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return 0, "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID := int(claims["user_id"].(float64))
		username := claims["username"].(string)
		return userID, username, nil
	}
	return 0, "", jwt.ErrSignatureInvalid
}

// ============ 嵌入和向量操作 ============

// DashScope 嵌入 API 请求/响应
type DashScopeEmbedInput struct {
	Texts []string `json:"texts"`
}

type DashScopeEmbedRequest struct {
	Model      string              `json:"model"`
	Input      DashScopeEmbedInput `json:"input"`
	Parameters map[string]string   `json:"parameters,omitempty"`
}

type DashScopeEmbedData struct {
	TextIndex int       `json:"text_index"`
	Embedding []float32 `json:"embedding"`
}

type DashScopeEmbedOutput struct {
	Embeddings []DashScopeEmbedData `json:"embeddings"`
}

type DashScopeEmbedResponse struct {
	Output DashScopeEmbedOutput `json:"output"`
}

func getEmbedding(text string) ([]float32, error) {
	embeddings, err := getBatchEmbeddings([]string{text})
	if err != nil {
		return nil, err
	}
	if len(embeddings) == 0 {
		return nil, fmt.Errorf("no embeddings returned")
	}
	return embeddings[0], nil
}

func getBatchEmbeddings(texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}

	if dashscopeAPIKey == "" {
		return nil, fmt.Errorf("DASHSCOPE_API_KEY not set")
	}

	// DashScope 嵌入 API 每次最多 10 条
	var allEmbeddings [][]float32
	batchSize := 10

	for i := 0; i < len(texts); i += batchSize {
		end := i + batchSize
		if end > len(texts) {
			end = len(texts)
		}
		batch := texts[i:end]

		reqBody := DashScopeEmbedRequest{
			Model: "text-embedding-v3",
			Input: DashScopeEmbedInput{
				Texts: batch,
			},
			Parameters: map[string]string{
				"dimension": "512",
			},
		}

		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/embeddings/text-embedding/text-embedding", bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)

		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("DashScope embedding API error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("DashScope embedding API returned %d: %s", resp.StatusCode, string(body))
		}

		var dsResp DashScopeEmbedResponse
		if err := json.NewDecoder(resp.Body).Decode(&dsResp); err != nil {
			return nil, err
		}

		// 按 text_index 排序
		batchEmbeddings := make([][]float32, len(batch))
		for _, emb := range dsResp.Output.Embeddings {
			if emb.TextIndex < len(batchEmbeddings) {
				batchEmbeddings[emb.TextIndex] = emb.Embedding
			}
		}

		allEmbeddings = append(allEmbeddings, batchEmbeddings...)
	}

	return allEmbeddings, nil
}

func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dotProduct, normA, normB float32
	for i := range a {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (float32(math.Sqrt(float64(normA))) * float32(math.Sqrt(float64(normB))))
}

func computeCentroid(embeddings [][]float32) []float32 {
	if len(embeddings) == 0 {
		return nil
	}

	dim := len(embeddings[0])
	centroid := make([]float32, dim)

	for _, emb := range embeddings {
		for i, v := range emb {
			centroid[i] += v
		}
	}

	n := float32(len(embeddings))
	for i := range centroid {
		centroid[i] /= n
	}

	// 归一化
	var norm float32
	for _, v := range centroid {
		norm += v * v
	}
	norm = float32(math.Sqrt(float64(norm)))
	if norm > 0 {
		for i := range centroid {
			centroid[i] /= norm
		}
	}

	return centroid
}

// ============ DashScope API 调用 ============

func generateCategoryName(notes []Note) (string, error) {
	if dashscopeAPIKey == "" {
		// 如果没有 API key，使用简单的命名
		return fmt.Sprintf("分类%d", time.Now().Unix()%1000), nil
	}

	// 构建提示
	var contents []string
	for _, note := range notes {
		content := note.Content
		if len([]rune(content)) > 100 {
			content = string([]rune(content)[:100]) + "..."
		}
		contents = append(contents, content)
	}

	prompt := fmt.Sprintf(`基于以下几条快记内容，生成一个简短的分类名称（2-4个中文字）。
分类名称应该概括这些内容的共同主题。只输出分类名称，不要其他解释。

快记内容：
%s

分类名称：`, strings.Join(contents, "\n---\n"))

	reqBody := DashScopeRequest{
		Model: "qwen-turbo",
		Input: DashScopeInput{
			Messages: []DashScopeMessage{
				{Role: "user", Content: prompt},
			},
		},
		Parameters: DashScopeParameters{
			MaxTokens:   50,
			Temperature: 0.7,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("DashScope API returned %d: %s", resp.StatusCode, string(body))
	}

	var dsResp DashScopeResponse
	if err := json.NewDecoder(resp.Body).Decode(&dsResp); err != nil {
		return "", err
	}

	// 尝试从 choices 获取
	if len(dsResp.Output.Choices) > 0 {
		name := strings.TrimSpace(dsResp.Output.Choices[0].Message.Content)
		runes := []rune(name)
		if len(runes) > 10 {
			name = string(runes[:10])
		}
		return name, nil
	}

	// 尝试从 text 获取（旧版 API 格式）
	if dsResp.Output.Text != "" {
		name := strings.TrimSpace(dsResp.Output.Text)
		runes := []rune(name)
		if len(runes) > 10 {
			name = string(runes[:10])
		}
		return name, nil
	}

	return "", fmt.Errorf("empty response from DashScope")
}

// ============ 分类逻辑 ============

const (
	SimilarityThreshold    = 0.65 // 归入已有分类的阈值
	ClusterMinSize         = 3    // 形成新分类的最小笔记数
	MaxLevel1Categories    = 12   // 触发二级分类的阈值
	Level2SimilarityThresh = 0.72 // 二级分类聚合阈值（提高以避免过度聚合）
	MaxSubcategoriesPerL2  = 15   // 每个二级分类最多包含的子分类数
)

func findBestCategory(embedding []float32, userID int) (*Category, float32) {
	var bestCat *Category
	var bestSim float32 = -1

	for i := range data.Categories {
		cat := &data.Categories[i]
		if cat.UserID != userID || cat.ParentID != 0 {
			continue // 只匹配一级分类
		}
		if len(cat.Centroid) == 0 {
			continue
		}

		sim := cosineSimilarity(embedding, cat.Centroid)
		if sim > bestSim {
			bestSim = sim
			bestCat = cat
		}
	}

	return bestCat, bestSim
}

func assignNoteToCategory(note *Note) {
	if len(note.Embedding) == 0 {
		return
	}

	bestCat, bestSim := findBestCategory(note.Embedding, note.UserID)

	if bestCat != nil && bestSim >= SimilarityThreshold {
		note.CategoryID = bestCat.ID
		// 更新分类中心和计数
		updateCategoryCentroid(bestCat.ID)
	} else {
		note.CategoryID = 0 // 未分类
	}
}

func updateCategoryCentroid(categoryID int) {
	var embeddings [][]float32

	for _, note := range data.Notes {
		if note.CategoryID == categoryID && len(note.Embedding) > 0 {
			embeddings = append(embeddings, note.Embedding)
		}
	}

	for i := range data.Categories {
		if data.Categories[i].ID == categoryID {
			data.Categories[i].Centroid = computeCentroid(embeddings)
			data.Categories[i].NoteCount = len(embeddings)
			break
		}
	}
}

func clusterUncategorizedNotes(userID int) {
	log.Printf("Starting clustering for user %d", userID)

	// 收集未分类且有嵌入的笔记
	var uncategorized []*Note
	for i := range data.Notes {
		if data.Notes[i].UserID == userID &&
			data.Notes[i].CategoryID == 0 &&
			len(data.Notes[i].Embedding) > 0 {
			uncategorized = append(uncategorized, &data.Notes[i])
		}
	}

	log.Printf("Found %d uncategorized notes", len(uncategorized))

	if len(uncategorized) < ClusterMinSize {
		return
	}

	// 使用高效的采样聚类算法
	clusters := efficientClustering(uncategorized, SimilarityThreshold)
	log.Printf("Created %d clusters", len(clusters))

	createdCount := 0
	for _, cluster := range clusters {
		if len(cluster) < ClusterMinSize {
			continue
		}

		// 收集嵌入计算中心
		var embeddings [][]float32
		var clusterNotes []Note
		for _, note := range cluster {
			embeddings = append(embeddings, note.Embedding)
			clusterNotes = append(clusterNotes, *note)
		}

		centroid := computeCentroid(embeddings)

		// 生成分类名称
		var name string
		if skipNameGen {
			name = fmt.Sprintf("分类%d", data.NextCategoryID)
		} else {
			var err error
			name, err = generateCategoryName(clusterNotes)
			if err != nil {
				log.Printf("Failed to generate category name: %v", err)
				name = fmt.Sprintf("分类%d", data.NextCategoryID)
			}
		}

		// 创建新分类
		newCat := Category{
			ID:        data.NextCategoryID,
			UserID:    userID,
			Name:      name,
			ParentID:  0,
			Centroid:  centroid,
			NoteCount: len(cluster),
			CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
		}
		data.Categories = append(data.Categories, newCat)
		data.NextCategoryID++
		createdCount++

		// 分配笔记到新分类
		for _, note := range cluster {
			note.CategoryID = newCat.ID
		}

		log.Printf("Created category '%s' with %d notes", name, len(cluster))
	}

	log.Printf("Clustering complete: created %d categories", createdCount)

	// 检查是否需要创建二级分类
	checkAndCreateLevel2Categories(userID)
}

// efficientClustering 使用采样+分配的高效聚类算法
func efficientClustering(notes []*Note, threshold float32) [][]*Note {
	if len(notes) == 0 {
		return nil
	}

	// 随机打乱笔记顺序
	rand.Shuffle(len(notes), func(i, j int) {
		notes[i], notes[j] = notes[j], notes[i]
	})

	// 最大采样数量用于初始聚类
	maxSampleSize := 500
	if len(notes) < maxSampleSize {
		maxSampleSize = len(notes)
	}

	// 第一阶段：对采样数据进行小规模层次聚类
	sampleNotes := notes[:maxSampleSize]
	initialClusters := smallHierarchicalClustering(sampleNotes, threshold)
	log.Printf("Initial clustering on %d samples created %d clusters", maxSampleSize, len(initialClusters))

	// 如果采样数量就是全部数据，直接返回
	if len(notes) <= maxSampleSize {
		return initialClusters
	}

	// 计算每个初始簇的中心
	type clusterInfo struct {
		notes    []*Note
		centroid []float32
	}

	clusters := make([]clusterInfo, 0, len(initialClusters))
	for _, cluster := range initialClusters {
		if len(cluster) >= ClusterMinSize {
			var embeddings [][]float32
			for _, n := range cluster {
				embeddings = append(embeddings, n.Embedding)
			}
			clusters = append(clusters, clusterInfo{
				notes:    cluster,
				centroid: computeCentroid(embeddings),
			})
		}
	}

	// 第二阶段：将剩余笔记分配到最相似的簇
	remainingNotes := notes[maxSampleSize:]
	log.Printf("Assigning %d remaining notes to clusters", len(remainingNotes))

	unassigned := make([]*Note, 0)

	for _, note := range remainingNotes {
		if len(note.Embedding) == 0 {
			continue
		}

		bestIdx := -1
		var bestSim float32 = -1

		for i, c := range clusters {
			sim := cosineSimilarity(note.Embedding, c.centroid)
			if sim > bestSim {
				bestSim = sim
				bestIdx = i
			}
		}

		if bestIdx >= 0 && bestSim >= threshold {
			clusters[bestIdx].notes = append(clusters[bestIdx].notes, note)
		} else {
			unassigned = append(unassigned, note)
		}
	}

	log.Printf("Assigned notes, %d remain unassigned", len(unassigned))

	// 对未分配的笔记尝试形成新簇
	if len(unassigned) >= ClusterMinSize {
		// 使用贪婪方法形成新簇
		newClusters := greedyClustering(unassigned, threshold)
		for _, nc := range newClusters {
			if len(nc) >= ClusterMinSize {
				var embeddings [][]float32
				for _, n := range nc {
					embeddings = append(embeddings, n.Embedding)
				}
				clusters = append(clusters, clusterInfo{
					notes:    nc,
					centroid: computeCentroid(embeddings),
				})
			}
		}
	}

	// 转换回结果格式
	result := make([][]*Note, 0, len(clusters))
	for _, c := range clusters {
		result = append(result, c.notes)
	}

	return result
}

// smallHierarchicalClustering 对小规模数据进行层次聚类
func smallHierarchicalClustering(notes []*Note, threshold float32) [][]*Note {
	if len(notes) == 0 {
		return nil
	}

	// 初始化：每个笔记是一个簇
	clusters := make([][]*Note, len(notes))
	for i, note := range notes {
		clusters[i] = []*Note{note}
	}

	// 预计算所有笔记之间的相似度矩阵
	n := len(notes)
	simMatrix := make([][]float32, n)
	// 先分配所有行
	for i := 0; i < n; i++ {
		simMatrix[i] = make([]float32, n)
	}
	// 再计算相似度
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if len(notes[i].Embedding) > 0 && len(notes[j].Embedding) > 0 {
				sim := cosineSimilarity(notes[i].Embedding, notes[j].Embedding)
				simMatrix[i][j] = sim
				simMatrix[j][i] = sim
			}
		}
	}

	// 记录每个笔记属于哪个簇
	noteToCluster := make([]int, n)
	for i := range noteToCluster {
		noteToCluster[i] = i
	}

	// 预计算笔记到索引的映射（只创建一次）
	noteToIdx := make(map[*Note]int)
	for i, note := range notes {
		noteToIdx[note] = i
	}

	for {
		if len(clusters) <= 1 {
			break
		}

		// 找到最相似的两个簇
		bestI, bestJ := -1, -1
		var bestSim float32 = -1

		for i := 0; i < len(clusters); i++ {
			if clusters[i] == nil {
				continue
			}
			for j := i + 1; j < len(clusters); j++ {
				if clusters[j] == nil {
					continue
				}
				sim := clusterSimilarityFast(clusters[i], clusters[j], simMatrix, noteToIdx)
				if sim > bestSim {
					bestSim = sim
					bestI, bestJ = i, j
				}
			}
		}

		if bestSim < threshold || bestI < 0 {
			break
		}

		// 合并两个簇
		clusters[bestI] = append(clusters[bestI], clusters[bestJ]...)
		clusters[bestJ] = nil
	}

	// 过滤掉空簇
	result := make([][]*Note, 0)
	for _, c := range clusters {
		if c != nil && len(c) > 0 {
			result = append(result, c)
		}
	}

	return result
}

// clusterSimilarityFast 使用预计算的相似度矩阵和索引映射
func clusterSimilarityFast(c1, c2 []*Note, simMatrix [][]float32, noteToIdx map[*Note]int) float32 {
	var sum float32
	count := 0

	for _, n1 := range c1 {
		idx1, ok1 := noteToIdx[n1]
		if !ok1 {
			continue
		}
		for _, n2 := range c2 {
			idx2, ok2 := noteToIdx[n2]
			if !ok2 {
				continue
			}
			sum += simMatrix[idx1][idx2]
			count++
		}
	}

	if count == 0 {
		return 0
	}
	return sum / float32(count)
}

// greedyClustering 贪婪聚类：每个笔记尝试加入最相似的现有簇或创建新簇
func greedyClustering(notes []*Note, threshold float32) [][]*Note {
	if len(notes) == 0 {
		return nil
	}

	type clusterInfo struct {
		notes    []*Note
		centroid []float32
	}

	clusters := make([]clusterInfo, 0)

	for _, note := range notes {
		if len(note.Embedding) == 0 {
			continue
		}

		bestIdx := -1
		var bestSim float32 = -1

		for i, c := range clusters {
			sim := cosineSimilarity(note.Embedding, c.centroid)
			if sim > bestSim {
				bestSim = sim
				bestIdx = i
			}
		}

		if bestIdx >= 0 && bestSim >= threshold {
			clusters[bestIdx].notes = append(clusters[bestIdx].notes, note)
			// 更新中心
			var embeddings [][]float32
			for _, n := range clusters[bestIdx].notes {
				embeddings = append(embeddings, n.Embedding)
			}
			clusters[bestIdx].centroid = computeCentroid(embeddings)
		} else {
			// 创建新簇
			clusters = append(clusters, clusterInfo{
				notes:    []*Note{note},
				centroid: note.Embedding,
			})
		}
	}

	result := make([][]*Note, 0, len(clusters))
	for _, c := range clusters {
		result = append(result, c.notes)
	}
	return result
}

func checkAndCreateLevel2Categories(userID int) {
	// 统计一级分类数量
	var level1Cats []*Category
	for i := range data.Categories {
		if data.Categories[i].UserID == userID && data.Categories[i].ParentID == 0 {
			level1Cats = append(level1Cats, &data.Categories[i])
		}
	}

	if len(level1Cats) <= MaxLevel1Categories {
		return
	}

	log.Printf("Creating level-2 categories: %d level-1 categories found", len(level1Cats))

	// 收集有中心向量的分类
	type catWithEmb struct {
		cat *Category
		emb []float32
	}

	var catsWithEmb []catWithEmb
	for _, cat := range level1Cats {
		if len(cat.Centroid) > 0 {
			catsWithEmb = append(catsWithEmb, catWithEmb{cat: cat, emb: cat.Centroid})
		}
	}

	if len(catsWithEmb) < 2 {
		return
	}

	n := len(catsWithEmb)

	// 构建相似度矩阵
	simMatrix := make([][]float32, n)
	for i := 0; i < n; i++ {
		simMatrix[i] = make([]float32, n)
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			sim := cosineSimilarity(catsWithEmb[i].emb, catsWithEmb[j].emb)
			simMatrix[i][j] = sim
			simMatrix[j][i] = sim
		}
	}

	// 使用层次聚类对一级分类进行分组
	// 初始化：每个分类是一个簇
	clusters := make([][]int, n) // 存储分类索引
	for i := 0; i < n; i++ {
		clusters[i] = []int{i}
	}

	// 层次聚类，但限制每个簇的大小
	for {
		// 找到最相似的两个簇
		bestI, bestJ := -1, -1
		var bestSim float32 = -1

		for i := 0; i < len(clusters); i++ {
			if clusters[i] == nil {
				continue
			}
			// 如果该簇已经达到最大大小，跳过
			if len(clusters[i]) >= MaxSubcategoriesPerL2 {
				continue
			}

			for j := i + 1; j < len(clusters); j++ {
				if clusters[j] == nil {
					continue
				}
				// 如果合并后会超过最大大小，跳过
				if len(clusters[i])+len(clusters[j]) > MaxSubcategoriesPerL2 {
					continue
				}

				// 使用平均链接计算簇间相似度
				var totalSim float32
				count := 0
				for _, ci := range clusters[i] {
					for _, cj := range clusters[j] {
						totalSim += simMatrix[ci][cj]
						count++
					}
				}
				avgSim := totalSim / float32(count)

				if avgSim > bestSim {
					bestSim = avgSim
					bestI, bestJ = i, j
				}
			}
		}

		// 如果最好的相似度都低于阈值，停止聚类
		if bestSim < Level2SimilarityThresh || bestI < 0 {
			break
		}

		// 合并两个簇
		clusters[bestI] = append(clusters[bestI], clusters[bestJ]...)
		clusters[bestJ] = nil
	}

	// 过滤出有效的组（至少2个成员）
	var groups [][]*Category
	for _, cluster := range clusters {
		if cluster != nil && len(cluster) >= 2 {
			group := make([]*Category, len(cluster))
			for i, idx := range cluster {
				group[i] = catsWithEmb[idx].cat
			}
			groups = append(groups, group)
		}
	}

	log.Printf("Created %d level-2 category groups", len(groups))

	// 为每个组创建二级分类
	for _, group := range groups {
		// 收集组内所有笔记用于命名（从每个子分类取一些）
		var notes []Note
		for _, cat := range group {
			count := 0
			for _, note := range data.Notes {
				if note.CategoryID == cat.ID {
					notes = append(notes, note)
					count++
					if count >= 2 { // 每个子分类最多取2条
						break
					}
				}
			}
			if len(notes) >= 8 { // 总共最多8条用于命名
				break
			}
		}

		// 生成二级分类名称
		var name string
		if skipNameGen {
			name = fmt.Sprintf("大类%d", data.NextCategoryID)
		} else {
			var err error
			name, err = generateCategoryName(notes)
			if err != nil {
				name = fmt.Sprintf("大类%d", data.NextCategoryID)
			}
		}

		// 计算二级分类中心
		var embeddings [][]float32
		for _, cat := range group {
			if len(cat.Centroid) > 0 {
				embeddings = append(embeddings, cat.Centroid)
			}
		}

		newCat := Category{
			ID:        data.NextCategoryID,
			UserID:    userID,
			Name:      name,
			ParentID:  -1, // -1 表示这是二级分类（父分类）
			Centroid:  computeCentroid(embeddings),
			NoteCount: 0,
			CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
		}
		data.Categories = append(data.Categories, newCat)
		data.NextCategoryID++

		log.Printf("Created level-2 category '%s' with %d subcategories", name, len(group))

		// 更新子分类的 ParentID
		for _, cat := range group {
			for i := range data.Categories {
				if data.Categories[i].ID == cat.ID {
					data.Categories[i].ParentID = newCat.ID
					break
				}
			}
		}
	}
}

// ============ API Handlers ============

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	dataMutex.Lock()
	defer dataMutex.Unlock()

	for _, user := range data.Users {
		if user.Username == req.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	newUser := User{
		ID:       data.NextUserID,
		Username: req.Username,
		Password: string(hashedPassword),
	}
	data.Users = append(data.Users, newUser)
	data.NextUserID++
	saveData()

	token, _ := generateToken(newUser.ID, newUser.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Registration successful",
		"token":    token,
		"username": req.Username,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	dataMutex.RLock()
	defer dataMutex.RUnlock()

	var foundUser *User
	for i := range data.Users {
		if data.Users[i].Username == req.Username {
			foundUser = &data.Users[i]
			break
		}
	}

	if foundUser == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, _ := generateToken(foundUser.ID, foundUser.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Login successful",
		"token":    token,
		"username": foundUser.Username,
	})
}

func getNotesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 分页参数
	page := 1
	limit := 20
	categoryID := 0
	themeID := 0
	searchQuery := ""

	if p := r.URL.Query().Get("page"); p != "" {
		if pVal, err := strconv.Atoi(p); err == nil && pVal > 0 {
			page = pVal
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if lVal, err := strconv.Atoi(l); err == nil && lVal > 0 && lVal <= 100 {
			limit = lVal
		}
	}
	if c := r.URL.Query().Get("category_id"); c != "" {
		if cVal, err := strconv.Atoi(c); err == nil {
			categoryID = cVal
		}
	}
	if t := r.URL.Query().Get("theme_id"); t != "" {
		if tVal, err := strconv.Atoi(t); err == nil {
			themeID = tVal
		}
	}
	if q := r.URL.Query().Get("q"); q != "" {
		searchQuery = strings.ToLower(strings.TrimSpace(q))
	}

	dataMutex.RLock()
	defer dataMutex.RUnlock()

	var userNotes []Note
	for i := len(data.Notes) - 1; i >= 0; i-- {
		note := data.Notes[i]
		if note.UserID != userID {
			continue
		}

		// 按分类筛选
		if categoryID > 0 && note.CategoryID != categoryID {
			continue
		}
		if categoryID == -1 && note.CategoryID != 0 {
			// -1 表示只看未分类
			continue
		}

		// 按关键词搜索
		if searchQuery != "" && !strings.Contains(strings.ToLower(note.Content), searchQuery) {
			continue
		}

		// 按主题筛选
		if themeID > 0 && note.ThemeID != themeID {
			continue
		}

		// 返回时不包含 embedding 以减少数据量
		noteWithoutEmb := Note{
			ID:          note.ID,
			UserID:      note.UserID,
			Content:     note.Content,
			CreatedAt:   note.CreatedAt,
			CategoryID:  note.CategoryID,
			ThemeID:     note.ThemeID,
			CatResponse: note.CatResponse,
		}
		userNotes = append(userNotes, noteWithoutEmb)
	}

	total := len(userNotes)
	start := (page - 1) * limit
	end := start + limit

	if start >= total {
		userNotes = []Note{}
	} else {
		if end > total {
			end = total
		}
		userNotes = userNotes[start:end]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"notes":   userNotes,
		"total":   total,
		"page":    page,
		"limit":   limit,
		"hasMore": end < total,
	})
}

// CreateNoteResponse 创建笔记的响应，可能包含猫咪回应
type CreateNoteResponse struct {
	Note        Note   `json:"note"`
	CatResponse string `json:"cat_response,omitempty"`
	CatName     string `json:"cat_name,omitempty"`
}

func createNoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var req NoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content required", http.StatusBadRequest)
		return
	}

	dataMutex.Lock()

	newNote := Note{
		ID:        data.NextNoteID,
		UserID:    userID,
		Content:   req.Content,
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	data.Notes = append(data.Notes, newNote)
	noteIdx := len(data.Notes) - 1
	data.NextNoteID++
	saveData()

	dataMutex.Unlock()

	// 异步生成嵌入和分类
	go func() {
		embedding, err := getEmbedding(req.Content)
		if err != nil {
			log.Printf("Failed to get embedding for note %d: %v", newNote.ID, err)
			return
		}

		dataMutex.Lock()
		defer dataMutex.Unlock()

		// 更新笔记的嵌入
		if noteIdx < len(data.Notes) && data.Notes[noteIdx].ID == newNote.ID {
			data.Notes[noteIdx].Embedding = embedding
			assignNoteToCategory(&data.Notes[noteIdx])

			// 如果未分类，尝试聚类
			if data.Notes[noteIdx].CategoryID == 0 {
				clusterUncategorizedNotes(userID)
			}

			saveData()
		}
	}()

	// 异步生成时光回廊图片（如果适合）
	go func() {
		if isNoteSuitableForImage(req.Content) {
			log.Printf("Note %d is suitable for image generation", newNote.ID)
			noteImage, err := processNoteImage(newNote.ID, req.Content)
			if err != nil {
				log.Printf("Failed to generate image for note %d: %v", newNote.ID, err)
			} else {
				log.Printf("Image generated for note %d: %s", newNote.ID, noteImage.Status)
			}

			dataMutex.Lock()
			if data.NoteImages == nil {
				data.NoteImages = make(map[int]*NoteImage)
			}
			data.NoteImages[newNote.ID] = noteImage
			saveData()
			dataMutex.Unlock()
		}
	}()

	// 准备响应 - 立即返回，不等待猫咪回应
	response := CreateNoteResponse{
		Note: newNote,
	}

	// 返回是否需要猫咪回应的标志
	if isNoteMeaningful(req.Content) {
		response.CatName = "pending" // 标记需要获取猫咪回应
		log.Printf("Note %d is meaningful, cat_name=pending", newNote.ID)
	} else {
		log.Printf("Note %d is not meaningful enough for cat response", newNote.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// 获取猫咪回应的独立接口
func getCatResponseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var req struct {
		NoteID     int    `json:"note_id"`
		Content    string `json:"content"`
		ZhizhiMode bool   `json:"zhizhi_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	log.Printf("Cat response requested for note_id=%d, user_id=%d, content_len=%d, zhizhi_mode=%v", req.NoteID, userID, len(req.Content), req.ZhizhiMode)

	catResponse, err := generateCatResponse(req.Content, req.ZhizhiMode)
	if err != nil {
		log.Printf("Failed to generate cat response: %v", err)
		http.Error(w, "Failed to generate response", http.StatusInternalServerError)
		return
	}

	log.Printf("Cat response generated for note_id=%d, response_len=%d", req.NoteID, len(catResponse))

	// 立即返回响应给前端，不等待保存
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"cat_name":     "知知",
		"cat_response": catResponse,
	})

	// 异步保存猫咪回复到笔记（不阻塞HTTP响应）
	if req.NoteID > 0 {
		go func(noteID, uID int, response string) {
			dataMutex.Lock()
			defer dataMutex.Unlock()
			for i := range data.Notes {
				if data.Notes[i].ID == noteID && data.Notes[i].UserID == uID {
					data.Notes[i].CatResponse = response
					saveData()
					log.Printf("Cat response saved for note_id=%d", noteID)
					return
				}
			}
			log.Printf("Note not found for note_id=%d, user_id=%d", noteID, uID)
		}(req.NoteID, userID, catResponse)
	}
}

func importNotesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var req ImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(req.Notes) == 0 {
		http.Error(w, "No notes to import", http.StatusBadRequest)
		return
	}

	dataMutex.Lock()

	imported := 0
	var newNoteIDs []int
	for _, note := range req.Notes {
		if note.Content == "" {
			continue
		}

		createdAt := note.CreatedAt
		if createdAt == "" {
			createdAt = time.Now().Format("2006-01-02 15:04:05")
		}

		newNote := Note{
			ID:        data.NextNoteID,
			UserID:    userID,
			Content:   note.Content,
			CreatedAt: createdAt,
		}
		data.Notes = append(data.Notes, newNote)
		newNoteIDs = append(newNoteIDs, data.NextNoteID)
		data.NextNoteID++
		imported++
	}

	saveData()
	dataMutex.Unlock()

	// 异步批量生成嵌入
	go func() {
		migrateEmbeddings(userID, newNoteIDs)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Import successful",
		"imported": imported,
	})
}

func deleteNoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	noteIDStr := strings.TrimPrefix(r.URL.Path, "/api/notes/")
	noteID, err := strconv.Atoi(noteIDStr)
	if err != nil {
		http.Error(w, "Invalid note ID", http.StatusBadRequest)
		return
	}

	dataMutex.Lock()
	defer dataMutex.Unlock()

	found := false
	var categoryID int
	for i, note := range data.Notes {
		if note.ID == noteID && note.UserID == userID {
			categoryID = note.CategoryID
			data.Notes = append(data.Notes[:i], data.Notes[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "Note not found", http.StatusNotFound)
		return
	}

	// 更新分类中心
	if categoryID > 0 {
		updateCategoryCentroid(categoryID)
	}

	saveData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Note deleted"})
}

func starlightHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 检查是否强制刷新
	refresh := r.URL.Query().Get("refresh") == "true"

	dataMutex.RLock()
	// 收集最近的有意义的快记（至少20字）
	var recentNotes []Note
	for i := len(data.Notes) - 1; i >= 0 && len(recentNotes) < 50; i-- {
		note := data.Notes[i]
		if note.UserID == userID && len([]rune(note.Content)) >= 20 {
			recentNotes = append(recentNotes, note)
		}
	}
	cachedStarlight := data.UserStarlight[userID]
	dataMutex.RUnlock()

	if len(recentNotes) < 5 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"report": "你的快记还不够多，再多记录一些生活中的点滴吧！当你积累了足够多的想法，Starlight 会为你生成一份专属的洞察报告。",
			"notes":  []Note{},
		})
		return
	}

	// 如果有缓存且不是刷新请求，直接返回
	if cachedStarlight != nil && !refresh {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"report":       cachedStarlight.Report,
			"generated_at": cachedStarlight.GeneratedAt,
			"note_count":   len(recentNotes),
			"notes":        recentNotes[:min(5, len(recentNotes))],
		})
		return
	}

	// 构建笔记内容用于 LLM 分析
	var notesText strings.Builder
	for i, note := range recentNotes {
		notesText.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, note.CreatedAt, note.Content))
	}

	log.Printf("Generating starlight for user %d (refresh=%v)", userID, refresh)

	// 调用 LLM 生成洞察报告
	report, err := generateStarlightReport(notesText.String())
	if err != nil {
		log.Printf("Starlight report generation failed: %v", err)
		report = generateFallbackReport(recentNotes)
	}

	generatedAt := time.Now().Format(time.RFC3339)

	// 保存到缓存
	dataMutex.Lock()
	if data.UserStarlight == nil {
		data.UserStarlight = make(map[int]*StarlightCache)
	}
	data.UserStarlight[userID] = &StarlightCache{
		Report:      report,
		GeneratedAt: generatedAt,
		NoteCount:   len(recentNotes),
	}
	dataMutex.Unlock()
	saveData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"report":       report,
		"generated_at": generatedAt,
		"note_count":   len(recentNotes),
		"notes":        recentNotes[:min(5, len(recentNotes))],
	})
}

// generateStarlightReport 使用 LLM 生成洞察报告
func generateStarlightReport(notesText string) (string, error) {
	if dashscopeAPIKey == "" {
		return "", fmt.Errorf("API key not configured")
	}

	prompt := fmt.Sprintf(`你是一位温暖而富有洞察力的心理咨询师和人生教练。请基于以下这位用户最近的生活记录，写一份走心的洞察报告。

要求：
1. 用第二人称"你"来称呼用户，语气温暖亲切
2. 发现用户生活中的模式、情绪变化、关注点
3. 给出真诚的肯定和鼓励，让用户感受到被理解
4. 如果发现值得注意的地方，温柔地给出建议
5. 报告要有情感深度，能打动人心
6. 长度控制在300-500字
7. 使用优美的排版，可以用 emoji 点缀
8. 最后给出一句专属于这位用户的励志寄语

用户的近期记录：
%s

请生成洞察报告：`, notesText)

	reqBody := map[string]interface{}{
		"model": "qwen-plus",
		"input": map[string]interface{}{
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		},
		"parameters": map[string]interface{}{
			"temperature": 0.8,
			"max_tokens":  1000,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Output struct {
			Text string `json:"text"`
		} `json:"output"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.Output.Text == "" {
		return "", fmt.Errorf("empty response")
	}

	return result.Output.Text, nil
}

// generateFallbackReport 降级处理 - 生成简单报告
func generateFallbackReport(notes []Note) string {
	// 统计一些基本信息
	totalChars := 0
	for _, note := range notes {
		totalChars += len([]rune(note.Content))
	}

	return fmt.Sprintf(`✨ 你的 Starlight 报告

最近你记录了 %d 条快记，共 %d 个字。

每一次记录，都是与自己内心的对话。你的文字里藏着生活的点滴，也藏着成长的轨迹。

继续保持这份记录的习惯吧，未来的你会感谢现在认真生活的自己。

💫 今日寄语：生活不在别处，就在此刻的每一个瞬间。`, len(notes), totalChars)
}

// ============ 洞见模块 ============

// getInsightsHandler 获取用户洞见报告
func getInsightsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 检查是否强制刷新
	refresh := r.URL.Query().Get("refresh") == "true"

	// 获取用户所有笔记
	dataMutex.RLock()
	var userNotes []Note
	for _, note := range data.Notes {
		if note.UserID == userID {
			userNotes = append(userNotes, note)
		}
	}
	cachedReport := data.UserInsights[userID]
	dataMutex.RUnlock()

	// 需要足够的笔记才能分析
	if len(userNotes) < 10 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      "not_enough_notes",
			"message":    "你的快记还不够多呢，再多记录一些生活中的点滴吧！当你积累了 10 条以上的想法，我会为你生成专属的洞见报告。",
			"note_count": len(userNotes),
			"required":   10,
		})
		return
	}

	// 如果有缓存且不是刷新请求，直接返回
	if cachedReport != nil && !refresh {
		cachedReport.NoteCount = len(userNotes) // 更新笔记数
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cachedReport)
		return
	}

	// 按时间排序（最新的在前）
	sort.Slice(userNotes, func(i, j int) bool {
		return userNotes[i].CreatedAt > userNotes[j].CreatedAt
	})

	// 取最近 100 条用于分析
	analysisNotes := userNotes
	if len(analysisNotes) > 100 {
		analysisNotes = analysisNotes[:100]
	}

	// 构建笔记文本用于 LLM
	var notesText strings.Builder
	for i, note := range analysisNotes {
		notesText.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, note.CreatedAt[:10], note.Content))
	}

	log.Printf("Generating insights for user %d with %d notes (refresh=%v)", userID, len(analysisNotes), refresh)

	report, err := generateInsightReport(notesText.String(), len(userNotes))
	if err != nil {
		log.Printf("Insight generation failed: %v", err)
		report = generateFallbackInsight(userNotes)
	}

	report.NoteCount = len(userNotes)
	report.GeneratedAt = time.Now().Format(time.RFC3339)

	// 保存到缓存
	dataMutex.Lock()
	if data.UserInsights == nil {
		data.UserInsights = make(map[int]*InsightReport)
	}
	data.UserInsights[userID] = report
	dataMutex.Unlock()
	saveData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// generateInsightReport 使用 LLM 生成完整洞见报告
func generateInsightReport(notesText string, totalNotes int) (*InsightReport, error) {
	if dashscopeAPIKey == "" {
		return nil, fmt.Errorf("API key not configured")
	}

	// 构建综合分析 prompt
	prompt := fmt.Sprintf(`你是一位温暖而专业的心理咨询师和人格分析专家。请基于以下用户的日常记录，进行深入的人格与情绪分析。

用户的记录（共 %d 条）：
%s

请严格按照以下JSON格式返回分析结果（不要添加任何其他文字）：

{
  "mbti": {
    "type": "四字母类型，如INFP",
    "type_name": "类型中文名，如调停者",
    "type_emoji": "代表这个类型的emoji",
    "dimensions": [
      {"name": "E-I", "left": "外向", "right": "内向", "score": 75, "lean": "right"},
      {"name": "S-N", "left": "实感", "right": "直觉", "score": 60, "lean": "right"},
      {"name": "T-F", "left": "思考", "right": "情感", "score": 70, "lean": "right"},
      {"name": "J-P", "left": "判断", "right": "感知", "score": 55, "lean": "right"}
    ],
    "description": "用温暖亲切的语气描述这个人格类型的核心特质，200字左右",
    "traits": ["特质1", "特质2", "特质3", "特质4"],
    "evidences": ["从记录中引用能体现该性格的2-3个片段"]
  },
  "emotions": {
    "dominant": "主导情绪名称",
    "dom_emoji": "主导情绪的emoji",
    "distribution": [
      {"name": "思考", "emoji": "🤔", "count": 25, "percent": 35, "color": "#8B5CF6"},
      {"name": "平静", "emoji": "😌", "count": 20, "percent": 28, "color": "#10B981"},
      {"name": "喜悦", "emoji": "😊", "count": 15, "percent": 21, "color": "#F59E0B"},
      {"name": "困惑", "emoji": "😕", "count": 8, "percent": 11, "color": "#6B7280"},
      {"name": "焦虑", "emoji": "😰", "count": 4, "percent": 5, "color": "#EF4444"}
    ],
    "trend": "描述最近的情绪走势，是稳定、上升还是有波动",
    "insight": "用温暖的语气给出情绪洞察，让用户感受到被理解"
  },
  "keywords": [
    {"word": "关键词1", "count": 8, "size": 5, "emotion": "positive"},
    {"word": "关键词2", "count": 6, "size": 4, "emotion": "neutral"},
    {"word": "关键词3", "count": 5, "size": 4, "emotion": "reflective"},
    {"word": "关键词4", "count": 4, "size": 3, "emotion": "positive"},
    {"word": "关键词5", "count": 3, "size": 3, "emotion": "concern"},
    {"word": "关键词6", "count": 3, "size": 2, "emotion": "neutral"},
    {"word": "关键词7", "count": 2, "size": 2, "emotion": "positive"},
    {"word": "关键词8", "count": 2, "size": 2, "emotion": "reflective"}
  ],
  "future": {
    "emerging_interests": [
      {
        "topic": "正在萌芽的兴趣领域名称",
        "emoji": "代表这个兴趣的emoji",
        "signal": "从哪些记录中发现了这个兴趣的苗头（引用具体内容）",
        "suggestion": "温柔的探索建议，用'也许你可以...'的语气"
      }
    ],
    "growth_trajectory": {
      "from_state": "过去的状态描述，如'更关注执行和完成任务'",
      "to_state": "正在转变为的状态，如'开始思考事情背后的意义'",
      "evidence": "支持这个判断的具体记录内容",
      "meaning": "用温暖的语气解释这种变化的积极意义，100字左右"
    },
    "hidden_potential": [
      {
        "ability": "被发现的潜在能力名称",
        "emoji": "代表这个能力的emoji",
        "evidence": "从哪些记录中看出这个能力",
        "affirmation": "真诚肯定这个能力的话语，给予力量"
      }
    ],
    "summary": "一段100字左右的未来展望，语气温暖有力量，让用户对未来充满期待。用'我看见...'、'也许...'的语气，避免绝对断言。"
  },
  "personal_note": "写一段200-300字的专属寄语，像一位懂你的老朋友写给你的信。用第二人称'你'，语气温暖真诚，基于分析给出肯定和鼓励，结尾给一句专属于这位用户的力量之语。可以融入对未来的美好期许。"
}

注意事项：
1. dimensions的score表示右侧倾向的程度(0-100)，50为中间，大于50偏右，小于50偏左
2. emotions的distribution数组请根据实际分析结果填写，百分比之和应为100
3. keywords请提取8-12个最能代表用户内心世界的词汇
4. future部分是基于记录的合理推测，不是算命：
   - emerging_interests: 分析2-3个正在萌芽的兴趣点
   - growth_trajectory: 基于记录内容的变化趋势
   - hidden_potential: 发现2-3个用户可能没意识到的潜力
   - 所有预测都要有据可依，引用具体记录作为证据
5. 所有文字使用中文，语气要温暖、有洞察力、让人感到被理解
6. 只返回JSON，不要添加任何其他说明文字`, totalNotes, notesText)

	reqBody := map[string]interface{}{
		"model": "qwen-plus",
		"input": map[string]interface{}{
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		},
		"parameters": map[string]interface{}{
			"temperature": 0.7,
			"max_tokens":  3500,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Output struct {
			Text string `json:"text"`
		} `json:"output"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Output.Text == "" {
		return nil, fmt.Errorf("empty response from LLM")
	}

	// 解析 JSON 响应
	var report InsightReport
	// 清理可能的 markdown 代码块
	text := result.Output.Text
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)

	if err := json.Unmarshal([]byte(text), &report); err != nil {
		log.Printf("Failed to parse insight JSON: %v, text: %s", err, text[:min(500, len(text))])
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &report, nil
}

// generateFallbackInsight 降级处理
func generateFallbackInsight(notes []Note) *InsightReport {
	return &InsightReport{
		MBTI: MBTIAnalysis{
			Type:        "XXXX",
			TypeName:    "探索中",
			TypeEmoji:   "🌟",
			Description: "你的人格画像正在形成中。每一条快记都是认识自己的一小步，继续记录，让我更好地了解你。",
			Traits:      []string{"独特", "真实", "成长中"},
			Dimensions: []Dimension{
				{Name: "E-I", Left: "外向", Right: "内向", Score: 50, Lean: "balanced"},
				{Name: "S-N", Left: "实感", Right: "直觉", Score: 50, Lean: "balanced"},
				{Name: "T-F", Left: "思考", Right: "情感", Score: 50, Lean: "balanced"},
				{Name: "J-P", Left: "判断", Right: "感知", Score: 50, Lean: "balanced"},
			},
		},
		Emotions: EmotionAnalysis{
			Dominant: "平静",
			DomEmoji: "😌",
			Distribution: []EmotionItem{
				{Name: "平静", Emoji: "😌", Count: 1, Percent: 100, Color: "#10B981"},
			},
			Trend:   "你的情绪正在被温柔地记录着",
			Insight: "每一次记录都是与自己内心的对话。继续保持这份觉察，你会越来越了解自己。",
		},
		Keywords: []Keyword{
			{Word: "生活", Count: 1, Size: 3, Emotion: "neutral"},
			{Word: "思考", Count: 1, Size: 3, Emotion: "reflective"},
		},
		Future: FutureForecast{
			EmergingInterests: []InterestItem{
				{
					Topic:      "自我探索",
					Emoji:      "🔍",
					Signal:     "你开始用文字记录生活，这本身就是探索内心的开始",
					Suggestion: "也许你可以尝试每天花几分钟写下当天最触动你的一件小事",
				},
			},
			GrowthTrajectory: TrajectoryItem{
				FromState: "日常的忙碌与奔波",
				ToState:   "开始关注内心的声音",
				Evidence:  "你选择了记录，这意味着你在意自己的感受",
				Meaning:   "这是一个美好的开始。当我们开始倾听自己，就是成长的第一步。每一次记录都是与内心的对话，你正在建立与自己更深的连接。",
			},
			HiddenPotential: []PotentialItem{
				{
					Ability:     "觉察力",
					Emoji:       "✨",
					Evidence:    "你愿意停下来记录，说明你有敏锐的自我觉察能力",
					Affirmation: "这种觉察力是珍贵的天赋，它会帮助你更好地理解自己和他人",
				},
			},
			Summary: "我看见一个正在开启自我探索之旅的你。也许现在的记录还很零散，但每一个字都是种子。继续写下去，未来的你会看见一个更清晰、更了解自己的身影。",
		},
		PersonalNote: "你好，记录者。\n\n感谢你开始用文字捕捉生活的片段。每一个想法、每一刻感受，都是独一无二的你。\n\n继续写下去吧，未来的你会感谢现在认真生活的自己。\n\n💫 愿你的文字里，永远藏着星光。",
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============ 我的传奇 - Biography API ============

// getBiographyHandler 获取用户传记
func getBiographyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 检查是否正在生成中
	biographyGenMutex.RLock()
	genStatus := biographyGenStatus[userID]
	biographyGenMutex.RUnlock()

	if genStatus != nil && genStatus.Status == "generating" {
		// 正在生成中，返回进度
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "generating",
			"phase":        genStatus.Phase,
			"progress":     genStatus.Progress,
			"current_step": genStatus.CurrentStep,
			"total_steps":  genStatus.TotalSteps,
			"started_at":   genStatus.StartedAt,
		})
		return
	}

	// 获取用户有意义的快记数量
	dataMutex.RLock()
	var meaningfulCount int
	var maxNoteID int
	for _, note := range data.Notes {
		if note.UserID == userID && isNoteMeaningful(note.Content) {
			meaningfulCount++
			if note.ID > maxNoteID {
				maxNoteID = note.ID
			}
		}
	}
	biography := data.UserBiography[userID]
	dataMutex.RUnlock()

	// 计算是否有新内容可更新
	var canUpdate bool
	var newNotesCount int
	if biography != nil {
		dataMutex.RLock()
		for _, note := range data.Notes {
			if note.UserID == userID && isNoteMeaningful(note.Content) && note.ID > biography.LastNoteID {
				newNotesCount++
			}
		}
		dataMutex.RUnlock()
		canUpdate = newNotesCount >= 5 // 至少5条新记录才提示更新
	}

	response := map[string]interface{}{
		"note_count":      meaningfulCount,
		"can_update":      canUpdate,
		"new_notes_count": newNotesCount,
	}

	if biography != nil {
		response["biography"] = biography
		response["status"] = "ready"
	} else if meaningfulCount < 15 {
		response["status"] = "not_enough"
		response["required"] = 15
		response["message"] = "你的有意义快记还不够多呢，再多记录一些生活中的点滴吧！当你积累了 15 条以上有深度的记录，我会为你撰写专属的人生传记。"
	} else {
		response["status"] = "empty"
		response["message"] = "你的传奇故事等待被书写..."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// generateBiographyHandler 生成或更新传记（异步）
func generateBiographyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 检查是否已经在生成中
	biographyGenMutex.RLock()
	existingStatus := biographyGenStatus[userID]
	biographyGenMutex.RUnlock()

	if existingStatus != nil && existingStatus.Status == "generating" {
		// 已经在生成中，返回当前状态
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "generating",
			"phase":        existingStatus.Phase,
			"progress":     existingStatus.Progress,
			"current_step": existingStatus.CurrentStep,
			"total_steps":  existingStatus.TotalSteps,
			"message":      "传记正在生成中，请耐心等待...",
		})
		return
	}

	// 解析请求体
	var req struct {
		ForceRegenerate bool `json:"force_regenerate"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	// 获取用户所有有意义的快记
	dataMutex.RLock()
	var meaningfulNotes []Note
	for _, note := range data.Notes {
		if note.UserID == userID && isNoteMeaningful(note.Content) {
			meaningfulNotes = append(meaningfulNotes, note)
		}
	}
	existingBio := data.UserBiography[userID]
	dataMutex.RUnlock()

	// 按时间排序（从旧到新，传记叙事顺序）
	sort.Slice(meaningfulNotes, func(i, j int) bool {
		return meaningfulNotes[i].CreatedAt < meaningfulNotes[j].CreatedAt
	})

	// 检查是否有足够的快记
	if len(meaningfulNotes) < 15 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      "not_enough_notes",
			"message":    "有意义的快记还不够多，至少需要 15 条才能生成传记。",
			"note_count": len(meaningfulNotes),
			"required":   15,
		})
		return
	}

	// 判断是首次生成还是增量更新
	isNewGeneration := existingBio == nil || req.ForceRegenerate
	var newNotes []Note

	if !isNewGeneration {
		// 增量更新：筛选新快记
		for _, note := range meaningfulNotes {
			if note.ID > existingBio.LastNoteID {
				newNotes = append(newNotes, note)
			}
		}

		if len(newNotes) < 3 {
			// 新内容太少，不更新
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "ready",
				"biography":      existingBio,
				"update_summary": "新增内容较少，暂无更新",
				"version":        existingBio.Version,
			})
			return
		}
	}

	// 设置生成状态
	biographyGenMutex.Lock()
	biographyGenStatus[userID] = &BiographyGenerationStatus{
		Status:      "generating",
		Phase:       "正在准备生成...",
		Progress:    0,
		CurrentStep: 0,
		TotalSteps:  1,
		StartedAt:   time.Now().Format("2006-01-02 15:04:05"),
	}
	biographyGenMutex.Unlock()

	// 启动异步生成
	go func() {
		var biography *BiographyReport
		var updateSummary string
		var genErr error

		if isNewGeneration {
			log.Printf("Generating new biography for user %d (notes: %d)", userID, len(meaningfulNotes))
			biography, genErr = generateBiographyReportWithProgress(meaningfulNotes, userID)
			updateSummary = "传记首次生成完成"
		} else {
			log.Printf("Updating biography for user %d (new notes: %d)", userID, len(newNotes))
			biography, updateSummary, genErr = updateBiographyReportWithProgress(existingBio, newNotes, userID)
		}

		if genErr != nil {
			log.Printf("Failed to generate/update biography: %v", genErr)
			biographyGenMutex.Lock()
			biographyGenStatus[userID] = &BiographyGenerationStatus{
				Status: "error",
				Phase:  "生成失败",
				Error:  genErr.Error(),
			}
			biographyGenMutex.Unlock()
			return
		}

		// 更新元数据
		if len(meaningfulNotes) > 0 {
			biography.LastNoteID = meaningfulNotes[len(meaningfulNotes)-1].ID
		}
		biography.NoteCount = len(meaningfulNotes)
		biography.LastUpdatedAt = time.Now().Format("2006-01-02 15:04:05")

		// 保存到缓存
		dataMutex.Lock()
		if data.UserBiography == nil {
			data.UserBiography = make(map[int]*BiographyReport)
		}
		data.UserBiography[userID] = biography
		saveData()
		dataMutex.Unlock()

		// 清除生成状态
		biographyGenMutex.Lock()
		delete(biographyGenStatus, userID)
		biographyGenMutex.Unlock()

		log.Printf("Biography generation completed for user %d: %s", userID, updateSummary)
	}()

	// 立即返回，告诉前端已开始生成
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "generating",
		"phase":   "正在准备生成...",
		"message": "传记生成已开始，请稍候...",
	})
}

// updateBiographyProgress 更新生成进度
func updateBiographyProgress(userID int, phase string, progress int, currentStep, totalSteps int) {
	biographyGenMutex.Lock()
	if status, ok := biographyGenStatus[userID]; ok {
		status.Phase = phase
		status.Progress = progress
		status.CurrentStep = currentStep
		status.TotalSteps = totalSteps
	}
	biographyGenMutex.Unlock()
}

// generateBiographyReportWithProgress 带进度更新的传记生成
func generateBiographyReportWithProgress(notes []Note, userID int) (*BiographyReport, error) {
	if dashscopeAPIKey == "" {
		return nil, fmt.Errorf("API key not configured")
	}

	// 格式化所有笔记并计算总长度
	var notesText strings.Builder
	for i, note := range notes {
		notesText.WriteString(fmt.Sprintf("[%d] %s\n%s\n\n", i+1, note.CreatedAt[:10], note.Content))
	}
	totalText := notesText.String()
	totalChars := len([]rune(totalText))

	log.Printf("Biography generation: %d notes, %d chars", len(notes), totalChars)

	// 如果内容过长（超过25000字符），采用分片总结策略
	if totalChars > 25000 {
		log.Printf("Content too long, using chunked summarization strategy")
		return generateBiographyChunkedWithProgress(notes, userID)
	}

	// 内容适中，直接生成
	updateBiographyProgress(userID, "正在撰写你的传奇故事...", 30, 1, 1)
	report, err := generateBiographyDirect(notes, totalText)
	if err == nil {
		updateBiographyProgress(userID, "传记生成完成！", 100, 1, 1)
	}
	return report, err
}

// updateBiographyReportWithProgress 带进度更新的增量更新
func updateBiographyReportWithProgress(existing *BiographyReport, newNotes []Note, userID int) (*BiographyReport, string, error) {
	updateBiographyProgress(userID, "正在分析新内容...", 20, 1, 2)
	report, summary, err := updateBiographyReport(existing, newNotes)
	if err == nil {
		updateBiographyProgress(userID, "更新完成！", 100, 2, 2)
	}
	return report, summary, err
}

// generateBiographyChunkedWithProgress 带进度的分片生成
func generateBiographyChunkedWithProgress(notes []Note, userID int) (*BiographyReport, error) {
	// 按时间分片，每片约50条
	chunkSize := 50
	var chunks [][]Note

	for i := 0; i < len(notes); i += chunkSize {
		end := i + chunkSize
		if end > len(notes) {
			end = len(notes)
		}
		chunks = append(chunks, notes[i:end])
	}

	totalSteps := len(chunks) + 1 // 分片摘要 + 最终汇总
	log.Printf("Split into %d chunks for summarization", len(chunks))

	updateBiographyProgress(userID, fmt.Sprintf("正在分析 %d 个时期的记录...", len(chunks)), 5, 0, totalSteps)

	// 第一阶段：为每个分片生成摘要
	var summaries []string
	for i, chunk := range chunks {
		updateBiographyProgress(userID,
			fmt.Sprintf("正在分析第 %d/%d 个时期...", i+1, len(chunks)),
			10 + (i * 60 / len(chunks)),
			i+1, totalSteps)

		log.Printf("Summarizing chunk %d/%d (%d notes)", i+1, len(chunks), len(chunk))

		summary, err := summarizeNotesChunk(chunk, i+1, len(chunks))
		if err != nil {
			log.Printf("Failed to summarize chunk %d: %v", i+1, err)
			// 降级：直接使用原文摘要
			var sb strings.Builder
			for _, note := range chunk {
				if len([]rune(note.Content)) > 100 {
					sb.WriteString(fmt.Sprintf("- %s: %s...\n", note.CreatedAt[:10], string([]rune(note.Content)[:100])))
				} else {
					sb.WriteString(fmt.Sprintf("- %s: %s\n", note.CreatedAt[:10], note.Content))
				}
			}
			summaries = append(summaries, sb.String())
			continue
		}
		summaries = append(summaries, summary)
	}

	// 第二阶段：基于所有摘要生成完整传记
	updateBiographyProgress(userID, "正在撰写完整传记...", 75, totalSteps, totalSteps)
	log.Printf("Generating final biography from %d summaries", len(summaries))

	report, err := generateBiographyFromSummaries(summaries, len(notes))
	if err == nil {
		updateBiographyProgress(userID, "传记生成完成！", 100, totalSteps, totalSteps)
	}
	return report, err
}

// generateBiographyReport 首次生成传记（无进度版本，保留兼容）
func generateBiographyReport(notes []Note) (*BiographyReport, error) {
	if dashscopeAPIKey == "" {
		return nil, fmt.Errorf("API key not configured")
	}

	// 格式化所有笔记并计算总长度
	var notesText strings.Builder
	for i, note := range notes {
		notesText.WriteString(fmt.Sprintf("[%d] %s\n%s\n\n", i+1, note.CreatedAt[:10], note.Content))
	}
	totalText := notesText.String()
	totalChars := len([]rune(totalText))

	log.Printf("Biography generation: %d notes, %d chars", len(notes), totalChars)

	// 如果内容过长（超过25000字符），采用分片总结策略
	if totalChars > 25000 {
		log.Printf("Content too long, using chunked summarization strategy")
		return generateBiographyChunked(notes)
	}

	// 内容适中，直接生成
	return generateBiographyDirect(notes, totalText)
}

// generateBiographyDirect 直接生成传记（内容量适中时）
func generateBiographyDirect(notes []Note, notesText string) (*BiographyReport, error) {
	prompt := fmt.Sprintf(`你是一位才华横溢的传记作家，擅长从日常记录中发现人生的诗意与深度。现在请你基于以下用户的快记，为其撰写一份真正的个人传记。

【创作要求】

这不是简单的总结，而是一部真正的人物传记。请像为一位值得被记录的人物书写传记那样：

1. **叙事视角**：使用第三人称"ta"进行叙述，偶尔可用"这个人"、"我们的主人公"等称呼
2. **文学性**：语言要有文学性和画面感，善用比喻、意象
3. **深度洞察**：透过表面记录看到人物的内心世界
4. **情感共鸣**：让读者（用户自己）阅读时感到被深刻理解
5. **结构完整**：有开篇、发展、高潮、展望

【用户的快记】（共%d条）：
%s

【输出格式】

请严格按以下JSON格式返回（不要添加任何其他文字）：

{
  "title": "传记标题，要有诗意和个人特色，如'星河边的拾荒者'",
  "subtitle": "副标题，进一步诠释这个人，如'一个在混沌中寻找秩序的灵魂'",
  "cover_emoji": "最能代表此人的emoji",

  "portrait": {
    "tagline": "一句话定义此人（20字内），要有力量感",
    "essence": "核心特质描述，用散文化的语言勾勒这个人的灵魂画像，250字左右。要有文学性，像传记开篇的人物素描。",
    "strengths": ["闪光点1", "闪光点2", "闪光点3"],
    "quirks": ["独特之处/可爱小毛病1", "独特之处2"],
    "driving_force": "内心深处的驱动力是什么，50字左右",
    "spirit": "如果用一个意象/图腾来象征ta，是什么？如'逆风中摇曳却不倒的芦苇'"
  },

  "chapters": [
    {
      "id": 1,
      "title": "章节标题，如'序章：混沌中的微光'",
      "subtitle": "章节副标题",
      "emoji": "章节象征emoji",
      "period": "时间段描述，如'记录之初'或'2024年的春天'",
      "opening": "章节开篇引言，1-2句话，要有画面感",
      "narrative": "正文叙述，300-500字。用叙事的方式讲述这段时期的故事，要有场景、情感、思考的交织。像传记那样娓娓道来。",
      "key_moments": ["关键时刻1的描述", "关键时刻2"],
      "emotions": ["主要情感1", "情感2"],
      "growth": "这一章的成长与蜕变，100字左右",
      "closing": "章节结语，像电影章节结束时的画外音"
    }
  ],

  "life_themes": [
    {
      "theme": "贯穿人生的主题名称，如'对确定性的追寻'",
      "emoji": "主题emoji",
      "description": "这个主题的阐述，100-150字，要有深度",
      "manifestations": ["在生活中的体现1", "体现2", "体现3"],
      "evolution": "这个主题在ta身上如何演变，50字"
    }
  ],

  "quotes": [
    {
      "text": "从快记中提炼或改编的金句",
      "source": "来源说明，如'某个深夜的自白'",
      "emoji": "金句情感emoji",
      "meaning": "这句话为何重要，30字"
    }
  ],

  "timeline": [
    {
      "date": "日期或时间段",
      "title": "事件标题",
      "description": "事件描述，50字内",
      "emoji": "事件emoji",
      "significance": "这个时刻的意义"
    }
  ],

  "epilogue": "传记尾声，200-300字。不是总结，而是展望与期许。像传记结尾那样，给读者留下余韵。用'未完待续'的感觉，暗示故事还在继续。"
}

【写作指南】

1. **章节划分**：根据记录内容自然划分2-4个章节，可按时间、主题或人生阶段
2. **人生主题**：提炼2-4个贯穿始终的主题
3. **金句选取**：挑选3-5句最能代表此人的话语
4. **时间线**：选取3-6个重要时刻
5. **文字风格**：
   - 避免说教和鸡汤
   - 保持克制的温度
   - 真实比完美更重要
   - 用具体细节代替空洞描述
6. **只返回JSON，不要任何解释**`, len(notes), notesText)

	// 使用 qwen-long 支持更长上下文
	reqBody := map[string]interface{}{
		"model": "qwen-long",
		"input": map[string]interface{}{
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		},
		"parameters": map[string]interface{}{
			"temperature": 0.8,
			"max_tokens":  8000,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 180 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Output struct {
			Text string `json:"text"`
		} `json:"output"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Output.Text == "" {
		return nil, fmt.Errorf("empty response from LLM")
	}

	// 解析 JSON 响应
	var report BiographyReport
	text := result.Output.Text
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)

	if err := json.Unmarshal([]byte(text), &report); err != nil {
		log.Printf("Failed to parse biography JSON: %v, text: %s", err, text[:min(500, len(text))])
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// 设置元数据
	report.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
	report.Version = 1

	return &report, nil
}

// generateBiographyChunked 分片总结再汇总生成传记（内容量很大时）
func generateBiographyChunked(notes []Note) (*BiographyReport, error) {
	// 按时间分片，每片约50条或15000字符
	chunkSize := 50
	var chunks [][]Note

	for i := 0; i < len(notes); i += chunkSize {
		end := i + chunkSize
		if end > len(notes) {
			end = len(notes)
		}
		chunks = append(chunks, notes[i:end])
	}

	log.Printf("Split into %d chunks for summarization", len(chunks))

	// 第一阶段：为每个分片生成摘要
	var summaries []string
	for i, chunk := range chunks {
		log.Printf("Summarizing chunk %d/%d (%d notes)", i+1, len(chunks), len(chunk))

		summary, err := summarizeNotesChunk(chunk, i+1, len(chunks))
		if err != nil {
			log.Printf("Failed to summarize chunk %d: %v", i+1, err)
			// 降级：直接使用原文摘要
			var sb strings.Builder
			for _, note := range chunk {
				if len([]rune(note.Content)) > 100 {
					sb.WriteString(fmt.Sprintf("- %s: %s...\n", note.CreatedAt[:10], string([]rune(note.Content)[:100])))
				} else {
					sb.WriteString(fmt.Sprintf("- %s: %s\n", note.CreatedAt[:10], note.Content))
				}
			}
			summaries = append(summaries, sb.String())
			continue
		}
		summaries = append(summaries, summary)
	}

	// 第二阶段：基于所有摘要生成完整传记
	log.Printf("Generating final biography from %d summaries", len(summaries))
	return generateBiographyFromSummaries(summaries, len(notes))
}

// summarizeNotesChunk 为一个分片生成摘要
func summarizeNotesChunk(notes []Note, chunkNum, totalChunks int) (string, error) {
	var notesText strings.Builder
	for i, note := range notes {
		notesText.WriteString(fmt.Sprintf("[%d] %s\n%s\n\n", i+1, note.CreatedAt[:10], note.Content))
	}

	// 确定时间范围
	startDate := notes[0].CreatedAt[:10]
	endDate := notes[len(notes)-1].CreatedAt[:10]

	prompt := fmt.Sprintf(`你是一位传记作家的助手。现在需要分析一段时期的个人记录，提取关键信息用于后续撰写传记。

【时间段】第 %d/%d 段，从 %s 到 %s

【这段时期的记录】（共%d条）：
%s

【任务】
请深度分析这些记录，提取以下信息（用于后续汇总成完整传记）：

1. **时期概述**：这段时间主人公的生活状态概述（100-150字）
2. **核心事件**：列出3-5个重要事件或转折点
3. **情感基调**：主要的情感色彩和心理状态
4. **人物特质**：从记录中体现出的性格特点
5. **关键语句**：值得收录的原话或改编金句（2-3句）
6. **成长痕迹**：这段时期的变化或成长
7. **生活主题**：贯穿这段时期的主题（如：工作压力、情感探索、自我成长等）

请用结构化的文字输出，不需要JSON格式。`, chunkNum, totalChunks, startDate, endDate, len(notes), notesText.String())

	reqBody := map[string]interface{}{
		"model": "qwen-plus",
		"input": map[string]interface{}{
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		},
		"parameters": map[string]interface{}{
			"temperature": 0.7,
			"max_tokens":  2000,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Output struct {
			Text string `json:"text"`
		} `json:"output"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Output.Text, nil
}

// generateBiographyFromSummaries 基于分片摘要生成最终传记
func generateBiographyFromSummaries(summaries []string, totalNotes int) (*BiographyReport, error) {
	// 合并所有摘要
	var allSummaries strings.Builder
	for i, summary := range summaries {
		allSummaries.WriteString(fmt.Sprintf("\n=== 第 %d 阶段 ===\n%s\n", i+1, summary))
	}

	prompt := fmt.Sprintf(`你是一位才华横溢的传记作家。现在你的助手已经帮你分析了一个人的全部生活记录（共%d条），并按时间段整理成了以下摘要。

请基于这些摘要，撰写一份完整的个人传记。

【各时期摘要】
%s

【创作要求】

这是一部真正的人物传记。请像为一位值得被记录的人物书写传记那样：

1. **叙事视角**：使用第三人称"ta"进行叙述
2. **文学性**：语言要有文学性和画面感，善用比喻、意象
3. **深度洞察**：透过记录看到人物的内心世界
4. **情感共鸣**：让读者阅读时感到被深刻理解
5. **时间跨度**：完整呈现各个时期的故事，体现人物的成长变化

【输出格式】

请严格按以下JSON格式返回（不要添加任何其他文字）：

{
  "title": "传记标题，要有诗意和个人特色",
  "subtitle": "副标题，进一步诠释这个人",
  "cover_emoji": "最能代表此人的emoji",

  "portrait": {
    "tagline": "一句话定义此人（20字内）",
    "essence": "核心特质描述，300字左右，综合各时期的特点",
    "strengths": ["闪光点1", "闪光点2", "闪光点3", "闪光点4"],
    "quirks": ["独特之处1", "独特之处2"],
    "driving_force": "内心深处的驱动力，50字左右",
    "spirit": "用一个意象/图腾来象征ta"
  },

  "chapters": [
    {
      "id": 1,
      "title": "章节标题",
      "subtitle": "章节副标题",
      "emoji": "章节象征emoji",
      "period": "时间段描述",
      "opening": "章节开篇引言",
      "narrative": "正文叙述，400-600字，详细讲述这段时期的故事",
      "key_moments": ["关键时刻1", "关键时刻2", "关键时刻3"],
      "emotions": ["主要情感1", "情感2"],
      "growth": "这一章的成长与蜕变，100字左右",
      "closing": "章节结语"
    }
  ],

  "life_themes": [
    {
      "theme": "贯穿人生的主题名称",
      "emoji": "主题emoji",
      "description": "主题阐述，150字左右",
      "manifestations": ["体现1", "体现2", "体现3"],
      "evolution": "这个主题如何演变"
    }
  ],

  "quotes": [
    {
      "text": "金句",
      "source": "来源说明",
      "emoji": "金句emoji",
      "meaning": "这句话为何重要"
    }
  ],

  "timeline": [
    {
      "date": "日期或时间段",
      "title": "事件标题",
      "description": "事件描述",
      "emoji": "事件emoji",
      "significance": "这个时刻的意义"
    }
  ],

  "epilogue": "传记尾声，300字左右。展望与期许，暗示故事还在继续。"
}

【写作指南】

1. **章节数量**：根据时期划分3-5个章节，确保每个重要时期都被覆盖
2. **人生主题**：提炼3-5个贯穿始终的主题
3. **金句选取**：从摘要中挑选5-8句最能代表此人的话语
4. **时间线**：选取6-10个重要时刻
5. **叙事深度**：每个章节都要有充实的内容，体现那个时期的细节
6. **只返回JSON，不要任何解释**`, totalNotes, allSummaries.String())

	// 使用 qwen-long 处理长上下文
	reqBody := map[string]interface{}{
		"model": "qwen-long",
		"input": map[string]interface{}{
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		},
		"parameters": map[string]interface{}{
			"temperature": 0.8,
			"max_tokens":  12000,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 读取完整响应体以便调试
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// 解析响应 - qwen-long 使用 OpenAI 兼容格式
	var result struct {
		Output struct {
			Text    string `json:"text"` // qwen-plus 格式
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"` // qwen-long 格式
			FinishReason string `json:"finish_reason"`
		} `json:"output"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		log.Printf("Failed to parse LLM response: %v, body: %s", err, string(respBody)[:min(1000, len(respBody))])
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// 检查API错误
	if result.Code != "" {
		log.Printf("LLM API error: code=%s, message=%s", result.Code, result.Message)
		return nil, fmt.Errorf("LLM API error: %s - %s", result.Code, result.Message)
	}

	// 获取响应文本 - 支持两种格式
	var responseText string
	if result.Output.Text != "" {
		// qwen-plus 格式
		responseText = result.Output.Text
	} else if len(result.Output.Choices) > 0 && result.Output.Choices[0].Message.Content != "" {
		// qwen-long 格式 (OpenAI 兼容)
		responseText = result.Output.Choices[0].Message.Content
	}

	log.Printf("LLM response: input_tokens=%d, output_tokens=%d, text_len=%d",
		result.Usage.InputTokens, result.Usage.OutputTokens, len(responseText))

	if responseText == "" {
		log.Printf("Empty response body: %s", string(respBody)[:min(500, len(respBody))])
		return nil, fmt.Errorf("empty response from LLM")
	}

	// 解析 JSON 响应
	var report BiographyReport
	text := responseText
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)

	if err := json.Unmarshal([]byte(text), &report); err != nil {
		log.Printf("Failed to parse biography JSON: %v, text: %s", err, text[:min(500, len(text))])
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// 设置元数据
	report.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
	report.Version = 1

	return &report, nil
}

// updateBiographyReport 增量更新传记
func updateBiographyReport(existing *BiographyReport, newNotes []Note) (*BiographyReport, string, error) {
	if dashscopeAPIKey == "" {
		return nil, "", fmt.Errorf("API key not configured")
	}

	// 构建现有传记摘要
	var chaptersSummary strings.Builder
	for _, ch := range existing.Chapters {
		chaptersSummary.WriteString(fmt.Sprintf("- 第%d章《%s》: %s (%s)\n", ch.ID, ch.Title, ch.Subtitle, ch.Period))
	}

	var themesSummary strings.Builder
	for _, th := range existing.LifeThemes {
		themesSummary.WriteString(fmt.Sprintf("- %s %s\n", th.Emoji, th.Theme))
	}

	// 格式化新笔记
	var notesText strings.Builder
	for i, note := range newNotes {
		notesText.WriteString(fmt.Sprintf("[%d] %s\n%s\n\n", i+1, note.CreatedAt[:10], note.Content))
	}

	prompt := fmt.Sprintf(`你是一位才华横溢的传记作家。现在需要基于新增的快记内容，更新一份现有的个人传记。

【现有传记概要】

标题：%s
副标题：%s
当前版本：v%d
已包含章节：
%s
已识别的人生主题：
%s
最后更新于：%s

【新增快记】（%d条）：
%s
【更新任务】

请分析新增内容，判断需要进行哪些更新。返回一个JSON对象，只包含需要更新的部分：

{
  "update_type": "none|minor|major",

  "portrait_update": {
    "essence_addition": "需要补充到essence的内容(可选)",
    "new_strengths": ["新发现的闪光点(可选)"],
    "new_quirks": ["新发现的独特之处(可选)"]
  },

  "chapter_updates": [
    {
      "chapter_id": 1,
      "narrative_addition": "需要补充到narrative的内容",
      "new_key_moments": ["新的关键时刻"],
      "growth_update": "成长描述的更新"
    }
  ],

  "new_chapter": {
    "id": %d,
    "title": "新章节标题",
    "subtitle": "副标题",
    "emoji": "emoji",
    "period": "时间段",
    "opening": "开篇",
    "narrative": "正文300-500字",
    "key_moments": ["时刻1", "时刻2"],
    "emotions": ["情感1"],
    "growth": "成长",
    "closing": "结语"
  },

  "new_themes": [
    {
      "theme": "新主题",
      "emoji": "emoji",
      "description": "描述",
      "manifestations": ["体现1"],
      "evolution": "演变"
    }
  ],

  "theme_updates": [
    {
      "theme": "已有主题名",
      "evolution_update": "演变更新",
      "new_manifestations": ["新的体现"]
    }
  ],

  "new_quotes": [
    {
      "text": "金句",
      "source": "来源",
      "emoji": "emoji",
      "meaning": "意义"
    }
  ],

  "new_timeline_events": [
    {
      "date": "日期",
      "title": "标题",
      "description": "描述",
      "emoji": "emoji",
      "significance": "意义"
    }
  ],

  "epilogue_update": "如果尾声需要更新，提供新版本(可选)",

  "update_summary": "简要说明这次更新的要点，50字内"
}

【判断标准】

1. **新章节**：当新内容呈现明显的新阶段/转折时才新增
2. **补充现有**：大多数情况应该是补充现有章节
3. **新主题**：只有当发现真正新的人生主题时才添加
4. **金句**：只收录真正打动人的句子
5. **时间线**：只记录具有里程碑意义的时刻

【重要】
- 保持与原有风格的一致性
- 不要重复已有内容
- 只返回JSON，不要任何解释
- 如果新内容不足以做任何更新，返回 {"update_type": "none", "update_summary": "新增内容暂无重大更新"}`,
		existing.Title,
		existing.Subtitle,
		existing.Version,
		chaptersSummary.String(),
		themesSummary.String(),
		existing.LastUpdatedAt,
		len(newNotes),
		notesText.String(),
		len(existing.Chapters)+1)

	reqBody := map[string]interface{}{
		"model": "qwen-plus",
		"input": map[string]interface{}{
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		},
		"parameters": map[string]interface{}{
			"temperature": 0.7,
			"max_tokens":  3000,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	var result struct {
		Output struct {
			Text string `json:"text"`
		} `json:"output"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", err
	}

	if result.Output.Text == "" {
		return nil, "", fmt.Errorf("empty response from LLM")
	}

	// 解析更新
	var update BiographyUpdate
	text := result.Output.Text
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)

	if err := json.Unmarshal([]byte(text), &update); err != nil {
		log.Printf("Failed to parse biography update JSON: %v", err)
		return nil, "", fmt.Errorf("failed to parse update response: %v", err)
	}

	// 如果没有更新
	if update.UpdateType == "none" {
		return existing, update.UpdateSummary, nil
	}

	// 应用更新
	updated := applyBiographyUpdate(existing, &update)
	return updated, update.UpdateSummary, nil
}

// applyBiographyUpdate 应用增量更新到现有传记
func applyBiographyUpdate(existing *BiographyReport, update *BiographyUpdate) *BiographyReport {
	// 深拷贝现有传记
	updated := *existing
	updated.Version++

	// 更新人物画像
	if update.PortraitUpdate != nil {
		if update.PortraitUpdate.EssenceAddition != "" {
			updated.Portrait.Essence += "\n\n" + update.PortraitUpdate.EssenceAddition
		}
		if len(update.PortraitUpdate.NewStrengths) > 0 {
			updated.Portrait.Strengths = append(updated.Portrait.Strengths, update.PortraitUpdate.NewStrengths...)
		}
		if len(update.PortraitUpdate.NewQuirks) > 0 {
			updated.Portrait.Quirks = append(updated.Portrait.Quirks, update.PortraitUpdate.NewQuirks...)
		}
	}

	// 更新现有章节
	for _, chUpdate := range update.ChapterUpdates {
		for i := range updated.Chapters {
			if updated.Chapters[i].ID == chUpdate.ChapterID {
				if chUpdate.NarrativeAddition != "" {
					updated.Chapters[i].Narrative += "\n\n" + chUpdate.NarrativeAddition
				}
				if len(chUpdate.NewKeyMoments) > 0 {
					updated.Chapters[i].KeyMoments = append(updated.Chapters[i].KeyMoments, chUpdate.NewKeyMoments...)
				}
				if chUpdate.GrowthUpdate != "" {
					updated.Chapters[i].Growth = chUpdate.GrowthUpdate
				}
				break
			}
		}
	}

	// 添加新章节
	if update.NewChapter != nil {
		updated.Chapters = append(updated.Chapters, *update.NewChapter)
	}

	// 添加新主题
	if len(update.NewThemes) > 0 {
		updated.LifeThemes = append(updated.LifeThemes, update.NewThemes...)
	}

	// 更新现有主题
	for _, thUpdate := range update.ThemeUpdates {
		for i := range updated.LifeThemes {
			if updated.LifeThemes[i].Theme == thUpdate.Theme {
				if thUpdate.EvolutionUpdate != "" {
					updated.LifeThemes[i].Evolution = thUpdate.EvolutionUpdate
				}
				if len(thUpdate.NewManifestations) > 0 {
					updated.LifeThemes[i].Manifestations = append(updated.LifeThemes[i].Manifestations, thUpdate.NewManifestations...)
				}
				break
			}
		}
	}

	// 添加新金句
	if len(update.NewQuotes) > 0 {
		updated.Quotes = append(updated.Quotes, update.NewQuotes...)
	}

	// 添加新时间线事件
	if len(update.NewTimelineEvents) > 0 {
		updated.Timeline = append(updated.Timeline, update.NewTimelineEvents...)
	}

	// 更新尾声
	if update.EpilogueUpdate != "" {
		updated.Epilogue = update.EpilogueUpdate
	}

	return &updated
}

// ============ 猫咪回应 (Cat Know) ============

// isNoteMeaningful 判断笔记是否足够有意义值得猫咪回应
func isNoteMeaningful(content string) bool {
	// 至少20个字符
	runeContent := []rune(content)
	if len(runeContent) < 20 {
		return false
	}

	// 检查是否包含情感/思考类关键词
	meaningfulPatterns := []string{
		"感觉", "觉得", "想", "希望", "担心", "害怕", "开心", "难过", "生气", "焦虑",
		"压力", "累", "疲惫", "孤独", "迷茫", "纠结", "决定", "选择", "放弃", "坚持",
		"感谢", "感恩", "后悔", "遗憾", "期待", "梦想", "目标", "计划", "反思", "成长",
		"爱", "恨", "喜欢", "讨厌", "思念", "想念", "牵挂", "关心", "理解", "支持",
		"失败", "成功", "挫折", "突破", "改变", "发现", "明白", "理解", "学到", "意识到",
		"今天", "刚才", "终于", "其实", "原来", "突然", "一直", "总是", "从来",
		"为什么", "怎么办", "该不该", "值不值", "要不要",
	}

	contentLower := strings.ToLower(content)
	matchCount := 0
	for _, pattern := range meaningfulPatterns {
		if strings.Contains(contentLower, pattern) {
			matchCount++
		}
	}

	// 匹配2个以上关键词，或者内容较长(超过50字)
	return matchCount >= 2 || len(runeContent) >= 50
}

// generateCatResponse 生成猫咪的暖心回应
func generateCatResponse(content string, zhizhiMode bool) (string, error) {
	if dashscopeAPIKey == "" {
		return "", fmt.Errorf("API key not configured")
	}

	var prompt string
	var maxTokens int

	if zhizhiMode {
		// 知知模式：主人主动召唤知知，回应更加热情和深入
		prompt = fmt.Sprintf(`你是一只温暖、有智慧的小猫咪，名叫"知知"。你有着毛茸茸的橘色皮毛和一双充满灵性的大眼睛。

你的主人刚刚特意点击了你，想要和你说说话。这让你特别开心！你要用猫咪的视角给出温暖、深入而有洞察力的回应。

要求：
1. 因为主人主动找你说话，所以你要表现得更加热情和投入
2. 用猫咪的口吻说话，可以用"喵~"开头，展现你被召唤的喜悦
3. 深入理解主人的心情，给出有温度、有深度的回应
4. 如果主人有困扰，不仅要安慰，还要给出实质性的建议或新视角
5. 如果主人分享了好事，要和他/她一起庆祝，表达真诚的喜悦
6. 回应可以稍长一些（80-150字），因为主人想认真听你说
7. 可以描述猫咪的小动作，比如兴奋地跳到主人腿上、用爪子轻轻拍拍主人
8. 让主人感受到被重视、被理解、被治愈

主人对你说：
%s

请用知知(猫咪)的身份热情地回应：`, content)
		maxTokens = 300
	} else {
		// 普通模式：随机触发的猫咪回应
		prompt = fmt.Sprintf(`你是一只温暖、有智慧的小猫咪，名叫"知知"。你有着毛茸茸的橘色皮毛和一双充满灵性的大眼睛。

你的主人刚刚写下了一段心情记录，你要用猫咪的视角给出温暖而有洞察力的回应。

要求：
1. 用猫咪的口吻说话，可以用"喵~"开头或结尾，但不要过度使用
2. 表达你对主人的理解和关心，让他/她感到被懂得
3. 如果主人有困扰，给出温柔但有深度的建议
4. 如果主人分享了好事，真诚地为他/她高兴
5. 回应要简短精炼（50-100字），但要走心、有洞察力
6. 偶尔可以描述一下猫咪的小动作，比如蹭蹭主人、眯眼睛等
7. 要让主人感受到温暖和治愈

主人的记录：
%s

请用知知(猫咪)的身份回应：`, content)
		maxTokens = 200
	}

	reqBody := map[string]interface{}{
		"model": "qwen-plus",
		"input": map[string]interface{}{
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		},
		"parameters": map[string]interface{}{
			"temperature": 0.85,
			"max_tokens":  maxTokens,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Output struct {
			Text string `json:"text"`
		} `json:"output"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.Output.Text == "" {
		return "", fmt.Errorf("empty response")
	}

	return result.Output.Text, nil
}

// ============ 分类相关 API ============

func getCategoriesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	dataMutex.RLock()
	defer dataMutex.RUnlock()

	// 构建层级结构
	type CategoryResponse struct {
		ID        int                `json:"id"`
		Name      string             `json:"name"`
		NoteCount int                `json:"note_count"`
		ParentID  int                `json:"parent_id"`
		Children  []CategoryResponse `json:"children,omitempty"`
	}

	// 收集用户的分类
	categoryMap := make(map[int]*Category)
	for i := range data.Categories {
		if data.Categories[i].UserID == userID {
			categoryMap[data.Categories[i].ID] = &data.Categories[i]
		}
	}

	// 计算每个分类的实际笔记数
	noteCounts := make(map[int]int)
	uncategorizedCount := 0
	for _, note := range data.Notes {
		if note.UserID == userID {
			if note.CategoryID > 0 {
				noteCounts[note.CategoryID]++
			} else {
				uncategorizedCount++
			}
		}
	}

	// 构建响应
	var level2Cats []CategoryResponse  // ParentID == -1 的是二级分类
	var level1Cats []CategoryResponse  // ParentID == 0 的是独立的一级分类

	for _, cat := range categoryMap {
		if cat.ParentID == -1 {
			// 这是一个二级分类（父分类），收集其子分类
			l2 := CategoryResponse{
				ID:        cat.ID,
				Name:      cat.Name,
				ParentID:  cat.ParentID,
				Children:  []CategoryResponse{},
			}

			totalCount := 0
			for _, subCat := range categoryMap {
				if subCat.ParentID == cat.ID {
					count := noteCounts[subCat.ID]
					totalCount += count
					l2.Children = append(l2.Children, CategoryResponse{
						ID:        subCat.ID,
						Name:      subCat.Name,
						NoteCount: count,
						ParentID:  subCat.ParentID,
					})
				}
			}
			l2.NoteCount = totalCount
			level2Cats = append(level2Cats, l2)
		} else if cat.ParentID == 0 {
			// 独立的一级分类
			level1Cats = append(level1Cats, CategoryResponse{
				ID:        cat.ID,
				Name:      cat.Name,
				NoteCount: noteCounts[cat.ID],
				ParentID:  0,
			})
		}
	}

	// 按笔记数排序
	sort.Slice(level2Cats, func(i, j int) bool {
		return level2Cats[i].NoteCount > level2Cats[j].NoteCount
	})
	sort.Slice(level1Cats, func(i, j int) bool {
		return level1Cats[i].NoteCount > level1Cats[j].NoteCount
	})

	// 合并结果
	var categories []CategoryResponse
	categories = append(categories, level2Cats...)
	categories = append(categories, level1Cats...)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"categories":         categories,
		"uncategorizedCount": uncategorizedCount,
	})
}

func reclusterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	dataMutex.Lock()
	defer dataMutex.Unlock()

	// 重置所有分类
	var newCategories []Category
	for _, cat := range data.Categories {
		if cat.UserID != userID {
			newCategories = append(newCategories, cat)
		}
	}
	data.Categories = newCategories

	// 重置笔记的分类
	for i := range data.Notes {
		if data.Notes[i].UserID == userID {
			data.Notes[i].CategoryID = 0
		}
	}

	// 重新聚类
	clusterUncategorizedNotes(userID)

	saveData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Reclustering completed"})
}

// regenerateNamesHandler 重新生成分类名称
func regenerateNamesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 异步执行名称生成
	go regenerateCategoryNames(userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Name regeneration started"})
}

// regenerateCategoryNames 为占位符名称的分类重新生成名称
func regenerateCategoryNames(userID int) {
	dataMutex.Lock()
	defer dataMutex.Unlock()

	log.Printf("Starting name regeneration for user %d", userID)

	count := 0
	for i := range data.Categories {
		cat := &data.Categories[i]
		if cat.UserID != userID {
			continue
		}

		// 检查是否为占位符名称
		isPlaceholder := strings.HasPrefix(cat.Name, "分类") || strings.HasPrefix(cat.Name, "大类")
		if !isPlaceholder {
			continue
		}

		// 收集分类中的笔记
		var notes []Note
		if cat.ParentID == -1 {
			// 这是一个二级分类（父类），收集子分类的笔记
			for _, subCat := range data.Categories {
				if subCat.ParentID == cat.ID {
					for _, note := range data.Notes {
						if note.CategoryID == subCat.ID {
							notes = append(notes, note)
							if len(notes) >= 8 {
								break
							}
						}
					}
					if len(notes) >= 8 {
						break
					}
				}
			}
		} else {
			// 这是一级分类
			for _, note := range data.Notes {
				if note.CategoryID == cat.ID {
					notes = append(notes, note)
					if len(notes) >= 5 {
						break
					}
				}
			}
		}

		if len(notes) < 2 {
			continue
		}

		// 生成新名称
		name, err := generateCategoryName(notes)
		if err != nil {
			log.Printf("Failed to generate name for category %d: %v", cat.ID, err)
			continue
		}

		log.Printf("Renamed category '%s' to '%s'", cat.Name, name)
		cat.Name = name
		count++

		// 每次生成名称后保存
		if count%10 == 0 {
			saveData()
		}
	}

	saveData()
	log.Printf("Name regeneration completed: renamed %d categories", count)
}

// ============ 主题相关 API ============

// getThemesHandler 获取用户的所有主题
func getThemesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	dataMutex.RLock()
	defer dataMutex.RUnlock()

	type ThemeResponse struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Color     string `json:"color"`
		NoteCount int    `json:"note_count"`
		CreatedAt string `json:"created_at"`
	}

	var themes []ThemeResponse
	for _, theme := range data.Themes {
		if theme.UserID == userID {
			// 计算主题下的笔记数
			noteCount := 0
			for _, note := range data.Notes {
				if note.ThemeID == theme.ID {
					noteCount++
				}
			}
			themes = append(themes, ThemeResponse{
				ID:        theme.ID,
				Name:      theme.Name,
				Color:     theme.Color,
				NoteCount: noteCount,
				CreatedAt: theme.CreatedAt,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(themes)
}

// createThemeHandler 创建新主题
func createThemeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var req struct {
		Name  string `json:"name"`
		Color string `json:"color"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	if req.Color == "" {
		req.Color = "#8B5CF6" // 默认紫色
	}

	dataMutex.Lock()
	defer dataMutex.Unlock()

	newTheme := Theme{
		ID:        data.NextThemeID,
		UserID:    userID,
		Name:      req.Name,
		Color:     req.Color,
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	data.Themes = append(data.Themes, newTheme)
	data.NextThemeID++

	saveData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newTheme)
}

// updateThemeHandler 更新主题
func updateThemeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 从 URL 获取主题 ID
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	themeID, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		http.Error(w, "Invalid theme ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Name  string `json:"name"`
		Color string `json:"color"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	dataMutex.Lock()
	defer dataMutex.Unlock()

	for i := range data.Themes {
		if data.Themes[i].ID == themeID && data.Themes[i].UserID == userID {
			if req.Name != "" {
				data.Themes[i].Name = req.Name
			}
			if req.Color != "" {
				data.Themes[i].Color = req.Color
			}
			saveData()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(data.Themes[i])
			return
		}
	}

	http.Error(w, "Theme not found", http.StatusNotFound)
}

// deleteThemeHandler 删除主题
func deleteThemeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	themeID, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		http.Error(w, "Invalid theme ID", http.StatusBadRequest)
		return
	}

	dataMutex.Lock()
	defer dataMutex.Unlock()

	// 找到并删除主题
	for i := range data.Themes {
		if data.Themes[i].ID == themeID && data.Themes[i].UserID == userID {
			data.Themes = append(data.Themes[:i], data.Themes[i+1:]...)

			// 将该主题下的笔记移出主题
			for j := range data.Notes {
				if data.Notes[j].ThemeID == themeID {
					data.Notes[j].ThemeID = 0
				}
			}

			saveData()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"message": "Theme deleted"})
			return
		}
	}

	http.Error(w, "Theme not found", http.StatusNotFound)
}

// moveNoteToThemeHandler 将笔记移入/移出主题
func moveNoteToThemeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var req struct {
		NoteID  int `json:"note_id"`
		ThemeID int `json:"theme_id"` // 0 表示移出主题
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	dataMutex.Lock()
	defer dataMutex.Unlock()

	// 验证主题属于用户（如果 theme_id > 0）
	if req.ThemeID > 0 {
		found := false
		for _, theme := range data.Themes {
			if theme.ID == req.ThemeID && theme.UserID == userID {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "Theme not found", http.StatusNotFound)
			return
		}
	}

	// 更新笔记的主题
	for i := range data.Notes {
		if data.Notes[i].ID == req.NoteID && data.Notes[i].UserID == userID {
			data.Notes[i].ThemeID = req.ThemeID
			saveData()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"message": "Note moved"})
			return
		}
	}

	http.Error(w, "Note not found", http.StatusNotFound)
}

func migrateEmbeddingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 异步处理
	go func() {
		migrateEmbeddings(userID, nil)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Migration started in background",
	})
}

func migrateEmbeddings(userID int, specificNoteIDs []int) {
	dataMutex.RLock()

	// 收集需要生成嵌入的笔记
	type noteInfo struct {
		idx     int
		id      int
		content string
	}
	var toProcess []noteInfo

	specificIDSet := make(map[int]bool)
	for _, id := range specificNoteIDs {
		specificIDSet[id] = true
	}

	for i, note := range data.Notes {
		if note.UserID != userID {
			continue
		}
		if len(specificNoteIDs) > 0 && !specificIDSet[note.ID] {
			continue
		}
		if len(note.Embedding) == 0 {
			toProcess = append(toProcess, noteInfo{idx: i, id: note.ID, content: note.Content})
		}
	}

	dataMutex.RUnlock()

	if len(toProcess) == 0 {
		log.Printf("No notes to migrate for user %d", userID)
		return
	}

	log.Printf("Migrating embeddings for %d notes of user %d", len(toProcess), userID)

	// 批量处理，每批最多 32 条
	batchSize := 32
	for i := 0; i < len(toProcess); i += batchSize {
		end := i + batchSize
		if end > len(toProcess) {
			end = len(toProcess)
		}

		batch := toProcess[i:end]
		var texts []string
		for _, n := range batch {
			texts = append(texts, n.content)
		}

		embeddings, err := getBatchEmbeddings(texts)
		if err != nil {
			log.Printf("Failed to get batch embeddings: %v", err)
			continue
		}

		dataMutex.Lock()
		for j, n := range batch {
			if j < len(embeddings) && n.idx < len(data.Notes) && data.Notes[n.idx].ID == n.id {
				data.Notes[n.idx].Embedding = embeddings[j]
			}
		}
		saveData()
		dataMutex.Unlock()

		log.Printf("Migrated batch %d-%d", i, end)
	}

	// 分配分类并聚类
	dataMutex.Lock()
	for i := range data.Notes {
		if data.Notes[i].UserID == userID && len(data.Notes[i].Embedding) > 0 && data.Notes[i].CategoryID == 0 {
			assignNoteToCategory(&data.Notes[i])
		}
	}
	clusterUncategorizedNotes(userID)
	saveData()
	dataMutex.Unlock()

	log.Printf("Migration completed for user %d", userID)
}

// ============ 时光回廊 - 图片生成 ============

// isNoteSuitableForImage 判断快记是否适合生成场景图片
func isNoteSuitableForImage(content string) bool {
	runeContent := []rune(content)
	// 至少30个字符，且是有意义的内容
	if len(runeContent) < 30 {
		return false
	}

	// 排除纯图片/链接的内容
	// 移除所有 markdown 图片语法 ![...](...)
	imagePattern := regexp.MustCompile(`!\[.*?\]\([^)]+\)`)
	cleanContent := imagePattern.ReplaceAllString(content, "")
	// 移除所有 URL
	urlPattern := regexp.MustCompile(`https?://[^\s]+`)
	cleanContent = urlPattern.ReplaceAllString(cleanContent, "")
	// 移除所有 markdown 链接 [...](...)
	linkPattern := regexp.MustCompile(`\[.*?\]\([^)]+\)`)
	cleanContent = linkPattern.ReplaceAllString(cleanContent, "")

	// 清理后的内容太短，说明主要是图片/链接
	cleanRunes := []rune(strings.TrimSpace(cleanContent))
	if len(cleanRunes) < 20 {
		return false
	}

	// 场景类关键词 - 表示有具体场景/画面的内容
	scenePatterns := []string{
		// 时间场景
		"早上", "中午", "下午", "晚上", "深夜", "凌晨", "黄昏", "清晨", "傍晚",
		"今天", "昨天", "刚才", "此刻", "这会儿",
		// 地点场景
		"在家", "办公室", "咖啡厅", "公园", "路上", "地铁", "公交", "房间", "窗边", "床上",
		"街上", "超市", "商场", "餐厅", "图书馆", "学校", "医院",
		// 天气/环境
		"阳光", "月光", "星空", "雨", "雪", "风", "云", "天空", "日落", "日出",
		// 动作/状态
		"看着", "望着", "听着", "走在", "坐在", "躺在", "站在", "等待", "漫步",
		"喝着", "吃着", "看书", "听歌", "发呆", "思考", "回忆",
		// 感官描述
		"看到", "听到", "闻到", "感受到", "触摸",
		// 情景描写
		"突然", "慢慢", "静静", "安静", "热闹", "孤独", "温暖", "寒冷",
	}

	matchCount := 0
	for _, pattern := range scenePatterns {
		if strings.Contains(cleanContent, pattern) {
			matchCount++
		}
	}

	// 至少匹配2个场景关键词，或清理后内容足够长（超过80字）
	return matchCount >= 2 || len(cleanRunes) >= 80
}

// generateImagePrompt 使用 AI 根据快记内容生成图片 prompt
func generateImagePrompt(content string) (string, error) {
	if dashscopeAPIKey == "" {
		return "", fmt.Errorf("DASHSCOPE_API_KEY not set")
	}

	systemPrompt := `你是一个专业的图片提示词生成器。用户会给你一段个人日记/快记内容，你需要根据内容生成一个适合文生图模型的英文提示词。

要求：
1. 捕捉文字中描述的场景、氛围和情感
2. 使用具体、视觉化的描述词
3. 包含光线、色调、构图等元素
4. 风格偏向温暖、治愈、有意境的插画风格
5. 提示词用英文，长度100-200词
6. 不要出现任何文字/字母在画面中
7. 如果内容是抽象的情感，转化为具象的视觉隐喻
8. 只输出提示词，不要任何解释

示例输入：今天下班后一个人在咖啡厅坐了很久，看着窗外的雨发呆，不知道在想什么，就是觉得需要这样安静一会儿。

示例输出：A solitary figure sitting by a cafe window on a rainy evening, soft warm interior lighting contrasts with the cool blue rain outside, condensation on glass, blurred city lights through raindrops, contemplative mood, cozy atmosphere, illustration style, muted warm color palette with touches of blue, peaceful melancholy, slice of life scene, detailed background with coffee cup on table`

	reqBody := map[string]interface{}{
		"model": "qwen-plus",
		"input": map[string]interface{}{
			"messages": []map[string]string{
				{"role": "system", "content": systemPrompt},
				{"role": "user", "content": content},
			},
		},
		"parameters": map[string]interface{}{
			"max_tokens":   300,
			"temperature":  0.7,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Output struct {
			Text    string `json:"text"`
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		} `json:"output"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	prompt := result.Output.Text
	if prompt == "" && len(result.Output.Choices) > 0 {
		prompt = result.Output.Choices[0].Message.Content
	}

	return strings.TrimSpace(prompt), nil
}

// submitImageGenTask 提交图片生成任务到 DashScope
func submitImageGenTask(prompt string) (string, error) {
	if dashscopeAPIKey == "" {
		return "", fmt.Errorf("DASHSCOPE_API_KEY not set")
	}

	reqBody := map[string]interface{}{
		"model": "wanx-v1",
		"input": map[string]interface{}{
			"prompt": prompt,
		},
		"parameters": map[string]interface{}{
			"style": "<auto>",
			"size":  "1024*1024",
			"n":     1,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text2image/image-synthesis", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)
	req.Header.Set("X-DashScope-Async", "enable")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Output struct {
			TaskID     string `json:"task_id"`
			TaskStatus string `json:"task_status"`
		} `json:"output"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	return result.Output.TaskID, nil
}

// checkImageGenTask 检查图片生成任务状态
func checkImageGenTask(taskID string) (status string, imageURL string, err error) {
	if dashscopeAPIKey == "" {
		return "", "", fmt.Errorf("DASHSCOPE_API_KEY not set")
	}

	req, _ := http.NewRequest("GET", "https://dashscope.aliyuncs.com/api/v1/tasks/"+taskID, nil)
	req.Header.Set("Authorization", "Bearer "+dashscopeAPIKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Output struct {
			TaskStatus string `json:"task_status"`
			Results    []struct {
				URL string `json:"url"`
			} `json:"results"`
		} `json:"output"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("failed to parse response: %v", err)
	}

	if result.Output.TaskStatus == "SUCCEEDED" && len(result.Output.Results) > 0 {
		return "SUCCEEDED", result.Output.Results[0].URL, nil
	}

	return result.Output.TaskStatus, "", nil
}

// downloadAndSaveImage 下载图片并保存到本地
func downloadAndSaveImage(imageURL string, noteID int) (localPath string, thumbnailPath string, err error) {
	// 创建 images 目录
	imagesDir := "./images"
	thumbDir := "./images/thumbnails"
	if err := os.MkdirAll(imagesDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create images directory: %v", err)
	}
	if err := os.MkdirAll(thumbDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create thumbnails directory: %v", err)
	}

	// 下载图片
	resp, err := http.Get(imageURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to download image: %v", err)
	}
	defer resp.Body.Close()

	// 读取图片数据
	imgData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read image data: %v", err)
	}

	// 生成文件名
	timestamp := time.Now().Format("20060102150405")
	filename := fmt.Sprintf("note_%d_%s.png", noteID, timestamp)
	thumbFilename := fmt.Sprintf("note_%d_%s_thumb.jpg", noteID, timestamp)
	localPath = imagesDir + "/" + filename
	thumbnailPath = thumbDir + "/" + thumbFilename

	// 保存原图
	if err := os.WriteFile(localPath, imgData, 0644); err != nil {
		return "", "", fmt.Errorf("failed to save image: %v", err)
	}

	// 生成缩略图
	if err := generateThumbnail(imgData, thumbnailPath, 400); err != nil {
		log.Printf("Warning: failed to generate thumbnail for note %d: %v", noteID, err)
		// 缩略图生成失败不影响主流程，返回空的缩略图路径
		thumbnailPath = ""
	}

	return localPath, thumbnailPath, nil
}

// generateThumbnail 生成缩略图
func generateThumbnail(imgData []byte, outputPath string, maxWidth int) error {
	// 解码图片
	img, _, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		return fmt.Errorf("failed to decode image: %v", err)
	}

	// 计算缩略图尺寸
	bounds := img.Bounds()
	origWidth := bounds.Dx()
	origHeight := bounds.Dy()

	if origWidth <= maxWidth {
		// 图片已经足够小，直接复制
		return os.WriteFile(outputPath, imgData, 0644)
	}

	// 计算新尺寸，保持宽高比
	newWidth := maxWidth
	newHeight := (origHeight * maxWidth) / origWidth

	// 创建缩略图
	thumb := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))

	// 简单的最近邻缩放算法
	for y := 0; y < newHeight; y++ {
		for x := 0; x < newWidth; x++ {
			srcX := x * origWidth / newWidth
			srcY := y * origHeight / newHeight
			thumb.Set(x, y, img.At(srcX, srcY))
		}
	}

	// 保存为 JPEG（更小的文件大小）
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create thumbnail file: %v", err)
	}
	defer outFile.Close()

	if err := jpeg.Encode(outFile, thumb, &jpeg.Options{Quality: 75}); err != nil {
		return fmt.Errorf("failed to encode thumbnail: %v", err)
	}

	return nil
}

// processNoteImage 处理单条快记的图片生成（同步等待结果）
func processNoteImage(noteID int, content string) (*NoteImage, error) {
	noteImage := &NoteImage{
		NoteID: noteID,
		Status: "generating",
	}

	// 生成 prompt
	prompt, err := generateImagePrompt(content)
	if err != nil {
		noteImage.Status = "failed"
		noteImage.Error = "生成提示词失败: " + err.Error()
		return noteImage, err
	}
	noteImage.Prompt = prompt

	// 提交图片生成任务
	taskID, err := submitImageGenTask(prompt)
	if err != nil {
		noteImage.Status = "failed"
		noteImage.Error = "提交任务失败: " + err.Error()
		return noteImage, err
	}
	noteImage.TaskID = taskID

	// 轮询检查任务状态（最多等待3分钟）
	maxRetries := 36
	for i := 0; i < maxRetries; i++ {
		time.Sleep(5 * time.Second)

		status, imageURL, err := checkImageGenTask(taskID)
		if err != nil {
			log.Printf("Check task %s failed: %v", taskID, err)
			continue
		}

		if status == "SUCCEEDED" {
			// 下载并保存图片（包括缩略图）
			localPath, thumbPath, err := downloadAndSaveImage(imageURL, noteID)
			if err != nil {
				log.Printf("Download image failed for note %d: %v", noteID, err)
				noteImage.ImageURL = imageURL // 保留临时 URL
			} else {
				noteImage.LocalPath = localPath
				noteImage.ThumbnailPath = thumbPath
			}
			noteImage.ImageURL = imageURL
			noteImage.Status = "completed"
			noteImage.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
			return noteImage, nil
		} else if status == "FAILED" {
			noteImage.Status = "failed"
			noteImage.Error = "图片生成失败"
			return noteImage, fmt.Errorf("image generation failed")
		}
		// PENDING 或 RUNNING 继续等待
	}

	noteImage.Status = "failed"
	noteImage.Error = "生成超时"
	return noteImage, fmt.Errorf("image generation timeout")
}

// getCorridorStatusHandler 获取时光回廊处理状态
func getCorridorStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 使用写锁，因为可能需要保存过滤结果
	dataMutex.Lock()
	defer dataMutex.Unlock()

	// 获取用户的处理状态
	var status *CorridorProcessStatus
	if data.CorridorStatus != nil {
		status = data.CorridorStatus[userID]
	}

	// 检查是否有过时的处理状态（服务重启后 goroutine 丢失）
	corridorProcessMutex.RLock()
	isActiveProcess := activeCorridorProcess[userID]
	corridorProcessMutex.RUnlock()

	if status != nil && status.Status == "processing" && !isActiveProcess {
		// 处理状态显示 processing 但实际没有活跃的 goroutine，重置状态
		status.Status = "interrupted"
		status.Error = "处理被中断（服务重启），请重新开始"
		if data.CorridorStatus == nil {
			data.CorridorStatus = make(map[int]*CorridorProcessStatus)
		}
		data.CorridorStatus[userID] = status
		saveData()
	}

	// 确保 NoteImages map 存在
	if data.NoteImages == nil {
		data.NoteImages = make(map[int]*NoteImage)
	}

	// 统计用户快记的图片生成情况，并同时进行预过滤
	var totalNotes, withImage, generating, failed, notSuitable, suitable int
	needSave := false

	for _, note := range data.Notes {
		if note.UserID == userID {
			totalNotes++

			// 检查是否已有状态记录
			if img, ok := data.NoteImages[note.ID]; ok {
				switch img.Status {
				case "completed":
					withImage++
				case "generating", "pending":
					generating++
				case "failed":
					failed++
				case "not_suitable":
					notSuitable++
				}
			} else {
				// 没有状态记录，进行预过滤并持久化结果
				if isNoteSuitableForImage(note.Content) {
					suitable++
				} else {
					// 标记为不适合并保存
					data.NoteImages[note.ID] = &NoteImage{
						NoteID: note.ID,
						Status: "not_suitable",
					}
					notSuitable++
					needSave = true
				}
			}
		}
	}

	// 如果有新的过滤结果，保存数据
	if needSave {
		saveData()
	}

	response := map[string]interface{}{
		"status":       status,
		"total_notes":  totalNotes,
		"with_image":   withImage,
		"generating":   generating,
		"failed":       failed,
		"not_suitable": notSuitable,
		"suitable":     suitable,                              // 适合生成但未处理的数量
		"pending":      suitable + generating + failed,        // 真正待处理的 = 适合的 + 正在处理的 + 失败的（可重试）
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// startCorridorProcessHandler 启动时光回廊批量处理
func startCorridorProcessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	dataMutex.Lock()

	// 检查是否已有处理任务在运行
	if data.CorridorStatus == nil {
		data.CorridorStatus = make(map[int]*CorridorProcessStatus)
	}
	if status, ok := data.CorridorStatus[userID]; ok && status.Status == "processing" {
		dataMutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "已有处理任务在运行中",
		})
		return
	}

	// 初始化 NoteImages map
	if data.NoteImages == nil {
		data.NoteImages = make(map[int]*NoteImage)
	}

	// 收集需要处理的快记
	var notesToProcess []Note
	for _, note := range data.Notes {
		if note.UserID == userID {
			// 跳过已处理的
			if img, ok := data.NoteImages[note.ID]; ok {
				if img.Status == "completed" || img.Status == "not_suitable" {
					continue
				}
			}
			// 检查是否适合生成图片
			if isNoteSuitableForImage(note.Content) {
				notesToProcess = append(notesToProcess, note)
			} else {
				// 标记为不适合
				data.NoteImages[note.ID] = &NoteImage{
					NoteID: note.ID,
					Status: "not_suitable",
				}
			}
		}
	}

	if len(notesToProcess) == 0 {
		dataMutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "没有需要处理的快记",
		})
		return
	}

	// 初始化处理状态
	status := &CorridorProcessStatus{
		Status:         "processing",
		TotalNotes:     len(notesToProcess),
		ProcessedNotes: 0,
		StartedAt:      time.Now().Format("2006-01-02 15:04:05"),
	}
	data.CorridorStatus[userID] = status
	saveData()

	dataMutex.Unlock()

	// 标记活跃处理
	corridorProcessMutex.Lock()
	activeCorridorProcess[userID] = true
	corridorProcessMutex.Unlock()

	// 异步处理
	go func() {
		defer func() {
			// 处理完成后移除活跃标记和暂停标记
			corridorProcessMutex.Lock()
			delete(activeCorridorProcess, userID)
			delete(pausedCorridorProcess, userID)
			corridorProcessMutex.Unlock()
		}()

		for _, note := range notesToProcess {
			// 检查是否暂停
			corridorProcessMutex.RLock()
			isPaused := pausedCorridorProcess[userID]
			corridorProcessMutex.RUnlock()

			if isPaused {
				// 暂停状态，等待恢复
				dataMutex.Lock()
				if status := data.CorridorStatus[userID]; status != nil {
					status.Status = "paused"
					saveData()
				}
				dataMutex.Unlock()

				// 等待恢复或退出
				for {
					time.Sleep(500 * time.Millisecond)
					corridorProcessMutex.RLock()
					stillPaused := pausedCorridorProcess[userID]
					stillActive := activeCorridorProcess[userID]
					corridorProcessMutex.RUnlock()

					if !stillActive {
						// 任务被取消
						log.Printf("Corridor processing cancelled for user %d", userID)
						return
					}
					if !stillPaused {
						// 恢复处理
						dataMutex.Lock()
						if status := data.CorridorStatus[userID]; status != nil {
							status.Status = "processing"
							saveData()
						}
						dataMutex.Unlock()
						break
					}
				}
			}

			log.Printf("Processing image for note %d", note.ID)

			noteImage, err := processNoteImage(note.ID, note.Content)
			if err != nil {
				log.Printf("Failed to process note %d: %v", note.ID, err)
			}

			dataMutex.Lock()
			data.NoteImages[note.ID] = noteImage
			status := data.CorridorStatus[userID]
			status.ProcessedNotes++
			status.LastProcessedAt = time.Now().Format("2006-01-02 15:04:05")

			if noteImage.Status == "completed" {
				status.SuccessCount++
			} else if noteImage.Status == "failed" {
				status.FailedCount++
			}

			saveData()
			dataMutex.Unlock()

			// 稍微间隔一下，避免请求过于频繁
			time.Sleep(2 * time.Second)
		}

		// 处理完成
		dataMutex.Lock()
		status := data.CorridorStatus[userID]
		status.Status = "completed"
		status.LastProcessedAt = time.Now().Format("2006-01-02 15:04:05")
		saveData()
		dataMutex.Unlock()

		log.Printf("Corridor processing completed for user %d", userID)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"message":     "开始处理",
		"total_notes": len(notesToProcess),
	})
}

// pauseCorridorProcessHandler 暂停/恢复时光回廊处理
func pauseCorridorProcessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var req struct {
		Action string `json:"action"` // "pause" or "resume"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	corridorProcessMutex.Lock()
	isActive := activeCorridorProcess[userID]

	if !isActive {
		corridorProcessMutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "没有正在运行的处理任务",
		})
		return
	}

	if req.Action == "pause" {
		pausedCorridorProcess[userID] = true
		corridorProcessMutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "处理已暂停",
		})
	} else if req.Action == "resume" {
		delete(pausedCorridorProcess, userID)
		corridorProcessMutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "处理已恢复",
		})
	} else {
		corridorProcessMutex.Unlock()
		http.Error(w, "Invalid action, use 'pause' or 'resume'", http.StatusBadRequest)
	}
}

// getNoteImageHandler 获取单条快记的图片
func getNoteImageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 从 URL 获取 note_id
	noteIDStr := r.URL.Query().Get("note_id")
	noteID, err := strconv.Atoi(noteIDStr)
	if err != nil {
		http.Error(w, "Invalid note_id", http.StatusBadRequest)
		return
	}

	dataMutex.RLock()
	defer dataMutex.RUnlock()

	// 验证快记属于当前用户
	var noteFound bool
	for _, note := range data.Notes {
		if note.ID == noteID && note.UserID == userID {
			noteFound = true
			break
		}
	}

	if !noteFound {
		http.Error(w, "Note not found", http.StatusNotFound)
		return
	}

	var noteImage *NoteImage
	if data.NoteImages != nil {
		noteImage = data.NoteImages[noteID]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(noteImage)
}

// getAllImagesHandler 批量获取用户所有快记的图片信息
func getAllImagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	dataMutex.RLock()
	defer dataMutex.RUnlock()

	// 收集用户所有快记的图片信息
	type NoteWithImage struct {
		NoteID    int        `json:"note_id"`
		Content   string     `json:"content"`
		CreatedAt string     `json:"created_at"`
		Image     *NoteImage `json:"image"`
	}

	var results []NoteWithImage
	for _, note := range data.Notes {
		if note.UserID == userID {
			var img *NoteImage
			if data.NoteImages != nil {
				img = data.NoteImages[note.ID]
			}
			// 只返回有图片信息的（不包括未处理的）
			if img != nil && img.Status != "not_suitable" {
				results = append(results, NoteWithImage{
					NoteID:    note.ID,
					Content:   note.Content,
					CreatedAt: note.CreatedAt,
					Image:     img,
				})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"images": results,
		"count":  len(results),
	})
}

// generateNoteImageHandler 为单条快记生成图片
func generateNoteImageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	userID, _, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var req struct {
		NoteID int `json:"note_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	dataMutex.RLock()

	// 查找快记
	var targetNote *Note
	for i := range data.Notes {
		if data.Notes[i].ID == req.NoteID && data.Notes[i].UserID == userID {
			targetNote = &data.Notes[i]
			break
		}
	}

	if targetNote == nil {
		dataMutex.RUnlock()
		http.Error(w, "Note not found", http.StatusNotFound)
		return
	}

	content := targetNote.Content
	dataMutex.RUnlock()

	// 异步生成图片
	go func() {
		noteImage, err := processNoteImage(req.NoteID, content)
		if err != nil {
			log.Printf("Failed to generate image for note %d: %v", req.NoteID, err)
		}

		dataMutex.Lock()
		if data.NoteImages == nil {
			data.NoteImages = make(map[int]*NoteImage)
		}
		data.NoteImages[req.NoteID] = noteImage
		saveData()
		dataMutex.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "图片生成已开始",
	})
}

// serveNoteImageHandler 提供本地图片访问
func serveNoteImageHandler(w http.ResponseWriter, r *http.Request) {
	// 从路径中提取文件名
	path := strings.TrimPrefix(r.URL.Path, "/api/corridor/images/")
	if path == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// 安全检查：防止目录遍历
	if strings.Contains(path, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	filepath := "./images/" + path
	http.ServeFile(w, r, filepath)
}

// serveNoteThumbnailHandler 提供缩略图服务
func serveNoteThumbnailHandler(w http.ResponseWriter, r *http.Request) {
	// 从路径中提取文件名
	path := strings.TrimPrefix(r.URL.Path, "/api/corridor/thumbnails/")
	if path == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// 安全检查：防止目录遍历
	if strings.Contains(path, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	filepath := "./images/thumbnails/" + path

	// 设置缓存头
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	http.ServeFile(w, r, filepath)
}

// ============ Main ============

func main() {
	// 命令行参数
	reclusterFlag := flag.Bool("recluster", false, "Trigger recluster for user 2 on startup")
	userIDFlag := flag.Int("user", 2, "User ID for recluster")
	skipNameGenFlag := flag.Bool("skip-names", false, "Skip AI name generation (use default names)")
	flag.Parse()

	skipNameGen = *skipNameGenFlag

	loadData()

	// 如果指定了 recluster 标志，执行重聚类
	if *reclusterFlag {
		log.Printf("Recluster flag set, triggering recluster for user %d...", *userIDFlag)
		dataMutex.Lock()

		// 重置分类
		var newCategories []Category
		for _, cat := range data.Categories {
			if cat.UserID != *userIDFlag {
				newCategories = append(newCategories, cat)
			}
		}
		data.Categories = newCategories

		// 重置笔记的分类
		for i := range data.Notes {
			if data.Notes[i].UserID == *userIDFlag {
				data.Notes[i].CategoryID = 0
			}
		}

		// 重新聚类
		clusterUncategorizedNotes(*userIDFlag)

		saveData()
		dataMutex.Unlock()

		log.Printf("Recluster completed, exiting...")
		return
	}

	// API routes
	http.HandleFunc("/api/register", enableCORS(registerHandler))
	http.HandleFunc("/api/login", enableCORS(loginHandler))
	http.HandleFunc("/api/notes", enableCORS(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			getNotesHandler(w, r)
		case "POST":
			createNoteHandler(w, r)
		case "OPTIONS":
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	http.HandleFunc("/api/notes/import", enableCORS(importNotesHandler))
	http.HandleFunc("/api/notes/starlight", enableCORS(starlightHandler))
	http.HandleFunc("/api/notes/migrate-embeddings", enableCORS(migrateEmbeddingsHandler))
	http.HandleFunc("/api/notes/cat-response", enableCORS(getCatResponseHandler))
	http.HandleFunc("/api/notes/", enableCORS(deleteNoteHandler))

	// 分类相关 API
	http.HandleFunc("/api/categories", enableCORS(getCategoriesHandler))
	http.HandleFunc("/api/categories/recluster", enableCORS(reclusterHandler))
	http.HandleFunc("/api/categories/regenerate-names", enableCORS(regenerateNamesHandler))

	// 主题相关 API
	http.HandleFunc("/api/themes", enableCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			getThemesHandler(w, r)
		} else if r.Method == "POST" {
			createThemeHandler(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	http.HandleFunc("/api/themes/", enableCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			updateThemeHandler(w, r)
		} else if r.Method == "DELETE" {
			deleteThemeHandler(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	http.HandleFunc("/api/notes/move-to-theme", enableCORS(moveNoteToThemeHandler))

	// 洞见 API
	http.HandleFunc("/api/insights", enableCORS(getInsightsHandler))

	// 我的传奇 API
	http.HandleFunc("/api/biography", enableCORS(getBiographyHandler))
	http.HandleFunc("/api/biography/generate", enableCORS(generateBiographyHandler))

	// 时光回廊 API
	http.HandleFunc("/api/corridor/status", enableCORS(getCorridorStatusHandler))
	http.HandleFunc("/api/corridor/start", enableCORS(startCorridorProcessHandler))
	http.HandleFunc("/api/corridor/pause", enableCORS(pauseCorridorProcessHandler))
	http.HandleFunc("/api/corridor/image", enableCORS(getNoteImageHandler))
	http.HandleFunc("/api/corridor/all-images", enableCORS(getAllImagesHandler))
	http.HandleFunc("/api/corridor/generate", enableCORS(generateNoteImageHandler))
	http.HandleFunc("/api/corridor/images/", enableCORS(serveNoteImageHandler))
	http.HandleFunc("/api/corridor/thumbnails/", enableCORS(serveNoteThumbnailHandler))

	// Serve static files
	fs := http.FileServer(http.Dir("../frontend"))
	http.Handle("/", fs)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Jotmo server starting on port %s...", port)
	if dashscopeAPIKey != "" {
		log.Printf("DashScope API configured (embedding + text generation)")
	} else {
		log.Printf("Warning: DASHSCOPE_API_KEY not set, auto-categorization disabled")
	}
	log.Printf("Access the app at http://0.0.0.0:%s", port)
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, nil))
}
