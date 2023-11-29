<?php

declare(strict_types=1);

/**
 * @copyright  2020 Ad Aures
 * @license    https://www.gnu.org/licenses/agpl-3.0.en.html AGPL3
 * @link       https://castopod.org/
 */

return [
    'all_podcasts' => '全部播客',
    'no_podcast' => '没有找到播客!',
    'create' => '创建播客',
    'import' => '导入播客',
    'all_imports' => '播客导入',
    'new_episode' => '新剧集',
    'view' => '浏览博客',
    'edit' => '编辑播客',
    'publish' => '发布播客',
    'publish_edit' => '编辑发布',
    'delete' => '删除播客',
    'see_episodes' => '查看剧集',
    'see_contributors' => '查看贡献者',
    'monetization_other' => 'Other monetization',
    'go_to_page' => '转到页面',
    'latest_episodes' => '最新剧集',
    'see_all_episodes' => '查看所有剧集',
    'draft' => '草稿',
    'messages' => [
        'createSuccess' => '播客创建成功！',
        'editSuccess' => '播客已更新！',
        'importSuccess' => '播客已导入！',
        'deleteSuccess' => '播客 @{podcast_handle} 已删除！',
        'deletePodcastMediaError' => '删除播客失败 {type, select,
            cover {封面}
            banner {横幅}
            other {媒体}
        }',
        'deleteEpisodeMediaError' => '无法删除博客剧集 {episode_slug} {type, select,
            transcript {字幕}
            chapters {章节}
            image {封面}
            audio {音频}
            other {媒体}
        }。',
        'deletePodcastMediaFolderError' => '无法删除播客媒体文件夹 {folder_path}。 你可以手动将其从磁盘中删除。',
        'podcastFeedUpdateSuccess' => '成功更新：{number_of_new_episodes, plural,
            one {#剧集}
            other {# 剧集}
        } 添加到播客！',
        'podcastFeedUpToDate' => '播客已经是最新状态。',
        'publishError' => '此播客已经发布或计划发布。',
        'publishEditError' => '此播客未计划发布。',
        'publishCancelSuccess' => '取消播客发布！',
        'scheduleDateError' => '计划日期必须设置！',
    ],
    'form' => [
        'identity_section_title' => '播客标识',
        'identity_section_subtitle' => '这些字段可能让你脱颖而出。',
        'fediverse_section_title' => 'Fediverse identity',

        'cover' => '播客封面',
        'cover_size_hint' => '封面必须是方形，而且至少 1400 px 宽度和高度。',
        'banner' => '播客横幅',
        'banner_size_hint' => '横幅必须有 3:1 比例，宽度至少为 1500px。',
        'banner_delete' => '删除播客横幅',
        'title' => '标题',
        'handle' => '标头',
        'handle_hint' =>
            '用于识别播客。允许使用大小写、数字和下划线。',
        'type' => [
            'label' => '类型',
            'episodic' => '剧集',
            'episodic_hint' => '如果在没有任何特定情况下进行剧集排序。那么最新剧集优先显示。',
            'serial' => '系列',
            'serial_hint' => '如果指定剧集排序方式。那么最久剧集将优先显示。',
        ],
        'description' => '描述',
        'classification_section_title' => '分类',
        'classification_section_subtitle' =>
            '这些字段将影响你的受众。',
        'language' => '切换语言',
        'category' => '类别',
        'category_placeholder' => '选择分类...',
        'other_categories' => '其他分类',
        'parental_advisory' => [
            'label' => '警告标记',
            'hint' => '是否包含限制级内容？',
            'undefined' => '未定义',
            'clean' => '重置为默认',
            'explicit' => '限制级',
        ],
        'author_section_title' => '作者',
        'author_section_subtitle' => '谁在管理播客？',
        'owner_name' => '所有者名称',
        'owner_name_hint' =>
            '仅供管理使用，在公开 RSS 摘要中可见。',
        'owner_email' => '所有者邮箱',
        'owner_email_hint' =>
            '大多数平台将使用它来验证播客的所有权。 在公开 RSS 摘要中可见。',
        'publisher' => '发布者',
        'publisher_hint' =>
            '负责制作节目的小组。 通常指播客的母公司或网络。 有时会被标记为“作者”。',
        'copyright' => '版权',
        'location_section_title' => '地点',
        'location_section_subtitle' => '这个播客在哪里？',
        'location_name' => '位置名称或地址',
        'location_name_hint' => '真或假的地方都可以',
        'monetization_section_title' => '货币化',
        'monetization_section_subtitle' =>
            '感谢你的听众支持。',
        'premium' => '高级版',
        'premium_by_default' => '剧集必须默认设置为付费会员订阅。',
        'premium_by_default_hint' => '默认情况下，播客剧集将被标记为高级。 你仍然可以选择将某些剧集、预告片等设置为公开。',
        'op3' => '打开播客前缀项目 (OP3)',
        'op3_hint' => '使用 OP3（一项开源且值得信赖的第三方分析服务）来评估您的分析数据。 与开源播客生态系统共享、验证和比较您的分析数据。',
        'op3_enable' => '启用 OP3 分析服务',
        'op3_enable_hint' => '出于安全原因，高级剧集的分析数据将不会与 OP3 共享。',
        'payment_pointer' => '网络货币化支付指南',
        'payment_pointer_hint' =>
            '借助网络货币化，你可以在此收款',
        'advanced_section_title' => '高级参数',
        'advanced_section_subtitle' =>
            '如果您需要 Castopod 无法处理的 RSS 标签，请在此处设置它们。',
        'custom_rss' => '播客的自定义 RSS 标签',
        'custom_rss_hint' => '这将被注入到 ❬channel❭ 标签中。',
        'new_feed_url' => '新摘要网址',
        'new_feed_url_hint' => '当你迁移到另一个域或播客托管平台时，请使用此字段。 默认情况下，播客导入时，该值为当前的 RSS 网址。',
        'old_feed_url' => '旧摘要网址',
        'partnership' => '合作伙伴',
        'partner_id' => 'ID',
        'partner_link_url' => '链接网址',
        'partner_image_url' => '图片网址',
        'partner_id_hint' => '你自己的合作伙伴 ID',
        'partner_link_url_hint' => '通用合作伙伴链接地址',
        'partner_image_url_hint' => '通用合作伙伴图片地址',
        'block' => '播客应该在公共目录中隐藏',
        'block_hint' =>
            '播客显示或隐藏状态：打开此选项可防止整个播客出现在 Apple 播客、Google 播客以及从此目录中提取剧集的任何第三方应用程序中。（不保证）',
        'complete' => '播客没有新剧集',
        'lock' => '防止播客被盗用',
        'lock_hint' =>
            '目的是告诉其他播客平台是否允许导入此摘要。 值为是表示拒绝将此摘要导入任何平台。',
        'submit_create' => '创建播客',
        'submit_edit' => '保存播客',
    ],
    'category_options' => [
        'uncategorized' => '未分类',
        'arts' => '艺术',
        'business' => '商业',
        'comedy' => '喜剧',
        'education' => '教育',
        'fiction' => '小说',
        'government' => '政府',
        'health_and_fitness' => '健康和健身',
        'history' => '历史',
        'kids_and_family' => '儿童与家庭',
        'leisure' => '休闲娱乐',
        'music' => '音乐',
        'news' => '新闻',
        'religion_and_spirituality' => '宗教与精神',
        'science' => '科学',
        'society_and_culture' => '社会与文化',
        'sports' => '体育运动',
        'technology' => '技术',
        'true_crime' => '真实犯罪',
        'tv_and_film' => '电视与电影',
        'books' => '图书',
        'design' => '设计',
        'fashion_and_beauty' => '时尚与美容',
        'food' => '美食',
        'performing_arts' => '表演艺术',
        'visual_arts' => '视觉艺术',
        'careers' => '职业生涯',
        'entrepreneurship' => '创业',
        'investing' => '金融投资',
        'management' => '管理',
        'marketing' => '市场营销',
        'non_profit' => '非盈利活动',
        'comedy_interviews' => '喜剧采访',
        'improv' => '即兴表演',
        'stand_up' => '单口相声',
        'courses' => '课程',
        'how_to' => '动手能力',
        'language_learning' => '语言学习',
        'self_improvement' => '自我提升',
        'comedy_fiction' => '喜剧小说',
        'drama' => '戏剧',
        'science_fiction' => '科幻',
        'alternative_health' => '保健',
        'fitness' => '健身',
        'medicine' => '医学',
        'mental_health' => '心理健康',
        'nutrition' => '营养学',
        'sexuality' => '性',
        'education_for_kids' => '儿童教育',
        'parenting' => '育儿',
        'pets_and_animals' => '宠物与动物',
        'stories_for_kids' => '童话故事',
        'animation_and_manga' => '动漫',
        'automotive' => '汽车',
        'aviation' => '航空',
        'crafts' => '工艺',
        'games' => '游戏',
        'hobbies' => '兴趣爱好',
        'home_and_garden' => '家居与园艺',
        'video_games' => '电子游戏',
        'music_commentary' => '音乐评论',
        'music_history' => '音乐史',
        'music_interviews' => '音乐采访',
        'business_news' => '商业新闻',
        'daily_news' => '每日新闻',
        'entertainment_news' => '娱乐新闻',
        'news_commentary' => '新闻评论',
        'politics' => '政治',
        'sports_news' => '体育新闻',
        'tech_news' => '科技新闻',
        'buddhism' => '佛教',
        'christianity' => '基督教',
        'hinduism' => '印度教',
        'islam' => '伊斯兰教',
        'judaism' => '犹太教',
        'religion' => '宗教信仰',
        'spirituality' => '精神生活',
        'astronomy' => '天文学',
        'chemistry' => '化学',
        'earth_sciences' => '地球科学',
        'life_sciences' => '生命科学',
        'mathematics' => '数学',
        'natural_sciences' => '自然科学',
        'nature' => '自然',
        'physics' => '物理学',
        'social_sciences' => '社会科学',
        'documentary' => '纪实',
        'personal_journals' => '个人日记',
        'philosophy' => '哲学',
        'places_and_travel' => '地方与旅行',
        'relationships' => '人际关系',
        'baseball' => '棒球',
        'basketball' => '篮球',
        'cricket' => '板球',
        'fantasy_sports' => '梦幻体育',
        'football' => '足球',
        'golf' => '高尔夫球',
        'hockey' => '曲棍球',
        'rugby' => '橄榄球',
        'running' => '跑步',
        'soccer' => '英式足球',
        'swimming' => '游泳',
        'tennis' => '网球',
        'volleyball' => '排球',
        'wilderness' => '荒野',
        'wrestling' => '摔跤',
        'after_shows' => '幕后',
        'film_history' => '电影史',
        'film_interviews' => '电影采访',
        'film_reviews' => '电影评论',
        'tv_reviews' => '电视评论',
    ],
    'publish_form' => [
        'back_to_podcast_dashboard' => '返回播客控制面板',
        'post' => '你的公告播文',
        'post_hint' =>
            "写一条消息来宣布您的播客发布。该消息将在您的播客主页中显示。",
        'message_placeholder' => '写下你的消息…',
        'submit' => '发布',
        'publication_date' => '发布日期',
        'publication_method' => [
            'now' => '现在',
            'schedule' => '计划',
        ],
        'scheduled_publication_date' => '计划发布日期',
        'scheduled_publication_date_hint' =>
            '你可以通过设置未来发布日期来安排播客发布。此字段必须格式为 YYYY-MM-DD HH:mm',
        'submit_edit' => '编辑发布',
        'cancel_publication' => '取消发布',
        'message_warning' => '你没有为你的公告播文写一条消息！',
        'message_warning_hint' => '有消息发送可以增加社交参与度，从而提高你的播客曝光度。',
        'message_warning_submit' => '仍然发布',
    ],
    'publication_status_banner' => [
        'draft_mode' => '草稿模式',
        'not_published' => '该播客尚未发布。',
        'scheduled' => '该播客计划在 {publication_date} 发布。',
    ],
    'delete_form' => [
        'disclaimer' =>
            "删除播客将删除相关的所有剧集、媒体文件、帖子和分析。 此操作不可逆，无法恢复。",
        'understand' => '我明白，我希望永久删除播客。',
        'submit' => '删除',
    ],
    'by' => '由 {publisher} 推出',
    'season' => '第 {seasonNumber} 季',
    'list_of_episodes_year' => '{year} 剧集 ({episodeCount})',
    'list_of_episodes_season' =>
        '第 {seasonNumber} 季(第 {episodeCount} 集)',
    'no_episode' => '没有找到剧集！',
    'follow' => '关注',
    'followers' => '{numberOfFollowers, plural,
        one {# 关注者}
        other {#关注者}
    }',
    'posts' => '{numberOfPosts, plural,
        one {# 帖子}
        other {# 帖子}
    }',
    'activity' => '活动',
    'episodes' => '剧集',
    'sponsor' => '赞助者',
    'funding_links' => '{podcastTitle} 的捐助链接',
    'find_on' => '找到 {podcastTitle} 在',
    'listen_on' => '收听',
];
