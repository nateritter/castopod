<?php

/**
 * @copyright  2020 Podlibre
 * @license    https://www.gnu.org/licenses/agpl-3.0.en.html AGPL3
 * @link       https://castopod.org/
 */

return [
    'previous_episode' => 'Previous episode',
    'previous_season' => 'Previous season',
    'next_episode' => 'Next episode',
    'next_season' => 'Next season',
    'season' => 'Season {seasonNumber}',
    'season_abbr' => 'S{seasonNumber}',
    'number' => 'Episode {episodeNumber}',
    'number_abbr' => 'Ep. {episodeNumber}',
    'season_episode' => 'Season {seasonNumber} episode {episodeNumber}',
    'season_episode_abbr' => 'S{seasonNumber}E{episodeNumber}',
    'all_podcast_episodes' => 'All podcast episodes',
    'back_to_podcast' => 'Go back to podcast',
    'edit' => 'Edit',
    'delete' => 'Delete',
    'go_to_page' => 'Go to page',
    'create' => 'Add an episode',
    'publication_status' => [
        'published' => 'Published on {0}',
        'scheduled' => 'Scheduled for {0}',
        'not_published' => 'Not published',
    ],
    'form' => [
        'enclosure' => 'Audio file',
        'enclosure_hint' => 'Choose an .mp3 or .m4a audio file.',
        'info_section_title' => 'Episode info',
        'info_section_subtitle' => '',
        'image' => 'Cover image',
        'image_hint' =>
            'If you do not set an image, the podcast cover will be used instead.',
        'title' => 'Title',
        'title_hint' =>
            'Should contain a clear and concise episode name. Do not specify the episode or season numbers here.',
        'slug' => 'Slug',
        'slug_hint' => 'Used for generating the episode URL.',
        'season_number' => 'Season',
        'episode_number' => 'Episode',
        'type' => [
            'label' => 'Type',
            'hint' =>
                '- <strong>full</strong>: complete content the episode.<br/>- <strong>trailer</strong>: short, promotional piece of content that represents a preview of the current show.<br/>- <strong>bonus</strong>: extra content for the show (for example, behind the scenes info or interviews with the cast) or cross-promotional content for another show.',
            'full' => 'Full',
            'trailer' => 'Trailer',
            'bonus' => 'Bonus',
        ],
        'show_notes_section_title' => 'Show notes',
        'show_notes_section_subtitle' =>
            'Up to 4000 characters, be clear and concise. Show notes help potential listeners in finding the episode.',
        'description' => 'Description',
        'description_footer' => 'Description footer',
        'description_footer_hint' =>
            'This text is added at the end of each episode description, it is a good place to input your social links for example.',
        'publication_section_title' => 'Publication info',
        'publication_section_subtitle' => '',
        'publication_date' => 'Publication date',
        'publication_date_clear' => 'Clear publication date',
        'publication_date_hint' =>
            'You can schedule the episode release by setting a future publication date. This field must be formatted as YYYY-MM-DD HH:mm',
        'parental_advisory' => [
            'label' => 'Parental advisory',
            'hint' => 'Does the episode contain explicit content?',
            'undefined' => 'undefined',
            'clean' => 'Clean',
            'explicit' => 'Explicit',
        ],
        'block' => 'Episode should be hidden from all platforms',
        'block_hint' =>
            'The episode show or hide status. If you want this episode removed from the Apple directory, toggle this on.',
        'additional_files_section_title' => 'Additional files',
        'additional_files_section_subtitle' =>
            'These files may be used by other platforms to provide better experience to your audience.<br />See the {podcastNamespaceLink} for more information.',
        'transcript' => 'Transcript or closed captions',
        'transcript_hint' => 'Allowed formats are txt, html, srt or json.',
        'transcript_delete' => 'Delete transcript',
        'chapters' => 'Chapters',
        'chapters_hint' => 'File should be in JSON Chapters Format.',
        'chapters_delete' => 'Delete chapters',
        'location_section_title' => 'Location',
        'location_section_subtitle' => 'What place is this episode about?',
        'location_name' => 'Location name or address',
        'location_name_hint' => 'This can be a real place or fictional',
        'advanced_section_title' => 'Advanced Parameters',
        'advanced_section_subtitle' =>
            'If you need RSS tags that Castopod does not handle, set them here.',
        'custom_rss' => 'Custom RSS tags for the episode',
        'custom_rss_hint' => 'This will be injected within the ❬item❭ tag.',
        'submit_create' => 'Create episode',
        'submit_edit' => 'Save episode',
    ],
    'soundbites' => 'Soundbites',
    'soundbites_form' => [
        'title' => 'Edit soundbites',
        'info_section_title' => 'Episode soundbites',
        'info_section_subtitle' => 'Add, edit or delete soundbites',
        'start_time' => 'Start',
        'start_time_hint' =>
            'The first second of the soundbite, it can be a decimal number.',
        'duration' => 'Duration',
        'duration_hint' =>
            'The duration of the soundbite (in seconds), it can be a decimal number.',
        'label' => 'Label',
        'label_hint' => 'Text that will be displayed.',
        'play' => 'Play soundbite',
        'delete' => 'Delete soundbite',
        'bookmark' =>
            'Click while playing to get current position, click again to get duration.',
        'submit_edit' => 'Save all soundbites',
    ],
    'embeddable_player' => [
        'add' => 'Add embeddable player',
        'title' => 'Embeddable player',
        'label' =>
            'Pick a theme color, copy the embeddable player to clipboard, then paste it on your website.',
        'clipboard_iframe' => 'Copy embeddable player to clipboard',
        'clipboard_url' => 'Copy address to clipboard',
        'dark' => 'Dark',
        'dark-transparent' => 'Dark transparent',
        'light' => 'Light',
        'light-transparent' => 'Light transparent',
    ],
];
