<?php declare(strict_types=1);

use CodeIgniter\I18n\Time;
use Modules\PodcastImport\Entities\PodcastImportTask;
use Modules\PodcastImport\Entities\TaskStatus;

?>

<?= data_table(
    [
        [
            'header' => lang('PodcastImport.queue.status.label'),
            'cell'   => function (PodcastImportTask $importTask) {
                $pillVariantMap = [
                    'queued'   => 'default',
                    'pending'  => 'warning',
                    'running'  => 'primary',
                    'canceled' => 'default',
                    'failed'   => 'danger',
                    'passed'   => 'success',
                ];

                $pillIconMap = [
                    'queued'   => 'timer',
                    'pending'  => 'pause',
                    'running'  => 'loader',
                    'canceled' => 'forbid',
                    'failed'   => 'close',
                    'passed'   => 'check',
                ];

                $pillIconClassMap = [
                    'queued'   => '',
                    'pending'  => '',
                    'running'  => 'animate-spin',
                    'canceled' => '',
                    'failed'   => '',
                    'passed'   => '',
                ];

                $errorHint = $importTask->status === TaskStatus::Failed ? hint_tooltip($importTask->error, 'ml-1') : '';

                return '<div class="flex items-center"><Pill variant="' . $pillVariantMap[$importTask->status->value] . '" icon="' . $pillIconMap[$importTask->status->value] . '" iconClass="' . $pillIconClassMap[$importTask->status->value] . '" hint="' . lang('PodcastImport.queue.status.' . $importTask->status->value . '_hint') . '">' . lang('PodcastImport.queue.status.' . $importTask->status->value) . '</Pill>' . $errorHint . '</div>';
            },
        ],
        [
            'header' => lang('PodcastImport.queue.feed'),
            'cell'   => function (PodcastImportTask $importTask) {
                return <<<HTML
                    <div class="flex flex-col">
                        <a href="{$importTask->feed_url}" class="flex items-center underline hover:no-underline" target="_blank" rel="noopener noreferrer">{$importTask->feed_url}<Icon glyph="external-link" class="ml-1"/></a>
                        <span class="text-sm text-gray-600">@{$importTask->handle}</span>
                    </div>
                HTML;
            },
        ],
        [
            'header' => lang('PodcastImport.queue.duration'),
            'cell'   => function (PodcastImportTask $importTask) {
                $duration = '-';
                if ($importTask->started_at !== null) {
                    if ($importTask->ended_at !== null) {
                        $duration = '<div class="flex flex-col text-xs gap-y-1">' .
                        '<div class="inline-flex items-center font-mono gap-x-1"><Icon glyph="timer" class="text-sm text-gray-400" />' . format_duration((int) $importTask->getDuration(), true) . '</div>' .
                        '<div class="inline-flex items-center gap-x-1"><Icon glyph="calendar" class="text-sm text-gray-400" />' . relative_time($importTask->ended_at) . '</div>' .
                        '</div>';
                    } else {
                        $duration = '<div class="inline-flex items-center font-mono text-xs gap-x-1"><Icon glyph="timer" class="text-sm text-gray-400" />' . format_duration(($importTask->started_at->difference(Time::now()))->getSeconds(), true) . '</div>';
                    }
                }

                return $duration;
            },
        ],
        [
            'header' => lang('PodcastImport.queue.imported_episodes'),
            'cell'   => function (PodcastImportTask $importTask) {
                if ($importTask->episodes_count) {
                    $progressPercentage = (int) ($importTask->getProgress() * 100) . '%';
                    $moreInfoHelper = hint_tooltip(lang('PodcastImport.queue.imported_episodes_hint', [
                        'newlyImportedCount'   => $importTask->episodes_newly_imported,
                        'alreadyImportedCount' => $importTask->episodes_already_imported,
                    ]), 'ml-1');
                    return <<<HTML
                    <div class="flex flex-col">
                        <span>{$progressPercentage}</span>
                        <p class="text-sm">
                            <span class="font-semibold">{$importTask->episodes_imported}</span> out of <span class="font-semibold">{$importTask->episodes_count}</span>
                            {$moreInfoHelper}
                        </p>
                    </div>
                    HTML;
                }

                return '-';
            },
        ],
        [
            'header' => lang('Common.list.actions'),
            'cell'   => function (PodcastImportTask $importTask) {
                return '<div class="inline-flex items-center gap-x-2">' .
                '<button id="more-dropdown-' . $importTask->id . '" type="button" class="inline-flex items-center p-1 rounded-full focus:ring-accent" data-dropdown="button" data-dropdown-target="more-dropdown-' . $importTask->id . '-menu" aria-haspopup="true" aria-expanded="false">' .
                        icon('more') .
                        '</button>' .
                        '<DropdownMenu id="more-dropdown-' . $importTask->id . '-menu" labelledby="more-dropdown-' . $importTask->id . '" offsetY="-24" items="' . esc(json_encode([
                            [
                                'type'  => 'link',
                                'title' => lang('PodcastImport.queue.actions.cancel'),
                                'uri'   => route_to('podcast-imports-task-action', $importTask->id, 'cancel'),
                            ],
                            [
                                'type'  => 'link',
                                'title' => lang('PodcastImport.queue.actions.retry'),
                                'uri'   => route_to('podcast-imports-task-action', $importTask->id, 'retry'),
                            ],
                            [
                                'type' => 'separator',
                            ],
                            [
                                'type'  => 'link',
                                'title' => lang('PodcastImport.queue.actions.delete'),
                                'uri'   => route_to('podcast-imports-task-action', $importTask->id, 'delete'),
                                'class' => 'font-semibold text-red-600',
                            ],
                        ])) . '" />' .
                    '</div>';
            },
        ],
    ],
    $podcastImportsQueue
) ?>
