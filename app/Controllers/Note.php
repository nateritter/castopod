<?php

/**
 * @copyright  2020 Podlibre
 * @license    https://www.gnu.org/licenses/agpl-3.0.en.html AGPL3
 * @link       https://castopod.org/
 */

namespace App\Controllers;

use App\Models\EpisodeModel;
use App\Models\PodcastModel;
use CodeIgniter\HTTP\URI;
use CodeIgniter\I18n\Time;

class Note extends \ActivityPub\Controllers\NoteController
{
    /**
     * @var \App\Entities\Podcast
     */
    protected $podcast;

    protected $helpers = ['auth', 'activitypub', 'svg', 'components', 'misc'];

    public function _remap($method, ...$params)
    {
        if (
            !($this->podcast = (new PodcastModel())->getPodcastByName(
                $params[0],
            ))
        ) {
            throw \CodeIgniter\Exceptions\PageNotFoundException::forPageNotFound();
        }

        $this->actor = $this->podcast->actor;

        if (count($params) > 1) {
            if (!($this->note = model('NoteModel')->getNoteById($params[1]))) {
                throw \CodeIgniter\Exceptions\PageNotFoundException::forPageNotFound();
            }
        }
        unset($params[0]);
        unset($params[1]);

        return $this->$method(...$params);
    }

    public function index()
    {
        helper('persons');
        $persons = [];
        construct_person_array($this->podcast->persons, $persons);

        $data = [
            'podcast' => $this->podcast,
            'actor' => $this->actor,
            'note' => $this->note,
            'persons' => $persons,
        ];

        // if user is logged in then send to the authenticated activity view
        if (can_user_interact()) {
            helper('form');
            return view('podcast/note_authenticated', $data);
        } else {
            return view('podcast/note', $data);
        }
    }

    public function attemptCreate()
    {
        $rules = [
            'message' => 'required|max_length[500]',
            'episode_url' => 'valid_url|permit_empty',
        ];

        if (!$this->validate($rules)) {
            return redirect()
                ->back()
                ->withInput()
                ->with('errors', $this->validator->getErrors());
        }

        $message = $this->request->getPost('message');

        $newNote = new \App\Entities\Note([
            'actor_id' => interact_as_actor_id(),
            'published_at' => Time::now(),
            'created_by' => user_id(),
        ]);

        // get episode if episodeUrl has been set
        $episodeUri = $this->request->getPost('episode_url');
        if (
            $episodeUri &&
            ($params = extract_params_from_episode_uri(new URI($episodeUri)))
        ) {
            if (
                $episode = (new EpisodeModel())->getEpisodeBySlug(
                    $params['podcastName'],
                    $params['episodeSlug'],
                )
            ) {
                $newNote->episode_id = $episode->id;
            }
        }

        $newNote->message = $message;

        if (
            !model('NoteModel')->addNote(
                $newNote,
                $newNote->episode_id ? false : true,
                true,
            )
        ) {
            return redirect()
                ->back()
                ->withInput()
                ->with('errors', model('NoteModel')->errors());
        }

        // Note has been successfully created
        return redirect()->back();
    }

    public function attemptReply()
    {
        $rules = [
            'message' => 'required|max_length[500]',
        ];

        if (!$this->validate($rules)) {
            return redirect()
                ->back()
                ->withInput()
                ->with('errors', $this->validator->getErrors());
        }

        $newNote = new \ActivityPub\Entities\Note([
            'actor_id' => interact_as_actor_id(),
            'in_reply_to_id' => $this->note->id,
            'message' => $this->request->getPost('message'),
            'published_at' => Time::now(),
            'created_by' => user_id(),
        ]);

        if (!model('NoteModel')->addReply($newNote)) {
            return redirect()
                ->back()
                ->withInput()
                ->with('errors', model('NoteModel')->errors());
        }

        // Reply note without preview card has been successfully created
        return redirect()->back();
    }

    public function attemptFavourite()
    {
        model('FavouriteModel')->toggleFavourite(
            interact_as_actor(),
            $this->note,
        );

        return redirect()->back();
    }

    public function attemptReblog()
    {
        model('NoteModel')->toggleReblog(interact_as_actor(), $this->note);

        return redirect()->back();
    }

    public function attemptAction()
    {
        $rules = [
            'action' => 'required|in_list[favourite,reblog,reply]',
        ];

        if (!$this->validate($rules)) {
            return redirect()
                ->back()
                ->withInput()
                ->with('errors', $this->validator->getErrors());
        }

        switch ($this->request->getPost('action')) {
            case 'favourite':
                return $this->attemptFavourite();
            case 'reblog':
                return $this->attemptReblog();
            case 'reply':
                return $this->attemptReply();
        }
    }

    public function remoteAction($action)
    {
        $data = [
            'podcast' => $this->podcast,
            'actor' => $this->actor,
            'note' => $this->note,
            'action' => $action,
        ];

        helper('form');

        return view('podcast/note_remote_action', $data);
    }
}